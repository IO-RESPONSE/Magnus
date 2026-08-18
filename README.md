# Magnus

Magnus is a **lightweight enterprise Web/Application Gateway** developed
independently by IORESPONSE.

## Current status

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
  the event loop on slow upstreams or large responses
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
- Container image: 9,207,512 bytes (~8.78 MiB), non-root, read-only rootfs

This is still a pre-production checkpoint. Long-running soak testing,
fault-injection beyond what `tests/test-core.sh` exercises, and comparative
benchmarking against other gateways have not been run, so this stage is
not described as production-ready. Target architecture and completion
criteria live in `docs/ENTERPRISE_ARCHITECTURE.md`.

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
