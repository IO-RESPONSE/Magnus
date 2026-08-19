# Changelog

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
