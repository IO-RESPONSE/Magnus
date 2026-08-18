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
- Non-blocking `/proxy/*` reverse proxy on the basic request/response path
- Policy modules (weighted round-robin, affinity, circuit breaker, rate
  limit) with unit tests, not yet wired to live routing
- Prometheus `/metrics` endpoint
- Container image: 9,197,428 bytes (~8.77 MiB), non-root, read-only rootfs

This is still a pre-production checkpoint. Proxy timeouts/502/504 handling,
active/passive upstream health, session affinity, control plane
(`magnusd`/`magnusctl`), fuzzing, and comparative benchmarking are not yet
complete, so this stage is not described as production-ready. Target
architecture and completion criteria live in `docs/ENTERPRISE_ARCHITECTURE.md`.

## Components

- `magnus`: the standalone HTTP/event data plane
- `magnusd`: control plane for config validation, deployment, certificates,
  and cluster state (planned)
- `magnusctl`: management CLI (planned)
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
