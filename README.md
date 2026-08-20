# Magnus

Magnus is a **lightweight enterprise Web/Application Gateway** developed
independently by IORESPONSE.

## Release: 1.0.0

## Features

- Independent C17/epoll event core with no dependency on an external web
  server runtime
- Strict HTTP/1.0/1.1 parser, keep-alive, 8KiB request cap
- Safe document root, MIME/HEAD, zero-copy `sendfile` static delivery
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
  header/cookie/query/source-CIDR, combinable with AND, first match
  wins) ahead of the built-in dispatch, actioned as proxy/deny/static
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
  bodies included, translated to/from h2 DATA frames. h2c and per-h2
  rate limiting/`/healthz`/`/metrics` are future increments
- HTTP/2 Rapid-Reset-class abuse hardening: a per-connection, one-second
  window caps both new-stream opens and client-sent `RST_STREAM` frames,
  terminating a connection that exceeds either (the CVE-2023-44487
  shape) while leaving ordinary traffic and every other connection
  unaffected; graceful shutdown sends a real GOAWAY frame to every open
  h2 connection before closing it
- Multi-endpoint cluster routing (weighted round-robin), wired to live
  traffic; active (periodic probe) and passive (live-traffic) health share
  one circuit-breaker state; cookie-based session affinity; per-client-IP
  ingress rate limiting
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
- Container image: 9,310,253 bytes (~8.88 MiB), non-root, read-only rootfs

See `CHANGELOG.md` for what shipped in 1.0.0. Longer-range direction and
completion criteria for future work live in `docs/ENTERPRISE_ARCHITECTURE.md`
and `docs/ROADMAP.md`.

## Components

- `magnus`: the standalone HTTP/event data plane. Configured by flags
  (`--port`, `--root`, `--tls-cert`/`--tls-key`, `--upstream`,
  `--rate-limit`) or by `--config <file>`, the only mode SIGHUP reload can
  target.
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
