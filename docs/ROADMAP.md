# Roadmap

## Shipped in 1.0.0

- Native C17/epoll data plane: HTTP/1.0/1.1, keep-alive, static
  delivery, TLS 1.2/1.3
- Non-blocking reverse proxy: timeouts, retry budget, header
  sanitization, streaming
- Multi-endpoint cluster: weighted round-robin, active+passive health,
  circuit breaker
- Traffic policy: cookie-based session affinity, per-client-IP rate
  limiting
- Control plane: `magnusd`/`magnusctl`, strict config schema, SIGHUP
  hot reload, health-checked rollback, audit log
- Observability/security: `/metrics` with a latency histogram, buffered
  and sampleable access log, admin-socket channel isolation, slowloris
  guard
- ASan/UBSan-clean test suite, HTTP parser mutation fuzzing

See `CHANGELOG.md` for the itemized list.

## Post-1.0

- Long-running soak testing and fault-injection beyond what
  `tests/test-core.sh` exercises
- Enterprise authN/authZ on the control channel: users, roles, OIDC/JWT,
  mTLS; change-approval workflow
- Certificate lifecycle automation and a secret-provider integration
- Multi-node control-plane deployment: state convergence across nodes,
  leader-failure recovery, canary rollout with automatic rollback,
  config backup/restore
- Native Module ABI beyond the current phase-hook SDK (routing, cache,
  identity handlers as pluggable modules)
- SBOM and signed-image release artifacts

Target architecture and completion criteria for the items above live in
`docs/ENTERPRISE_ARCHITECTURE.md`.
