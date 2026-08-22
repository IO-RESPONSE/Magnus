# Phase 4 (HTTP/3/QUIC) — Spike Results

Standalone verification of `docs/phase4-http3-quic-dependency-evaluation.md`
item 1, run 2026-08-22. Entirely outside `src/`: no change to `magnus.c`,
`Makefile`, or the container build. Scope is exactly what the evaluation
doc asked for — does ngtcp2 + `libngtcp2_crypto_ossl` + nghttp3 actually
work against a real, current OpenSSL, or is the "experimental" label
hiding a dead end.

## Environment

- Host OpenSSL: 3.5.5 (already ≥ the container's Debian 13 3.5.4/3.5.6,
  per the evaluation doc's item 4)
- `ngtcp2` 1.19.0, `ngtcp2-crypto-ossl` 1.19.0 — EPEL RPMs for EL10
  (`ngtcp2-devel`, `ngtcp2-crypto-ossl-devel`)
- `nghttp3` 1.19.0 — no RPM exists; built from upstream source
  (`autoreconf -i && ./configure --enable-lib-only && make`), version
  matched to ngtcp2's own release
- `libev-devel` 4.33 — EPEL/CRB RPM, needed only to build ngtcp2's own
  reference example client/server (`examples/osslclient`,
  `examples/osslserver`), not a Phase 4 candidate dependency itself;
  Magnus's own integration would use its existing epoll reactor, not
  libev
- Everything above ran in a disposable scratch directory outside the
  `magnus` git repository; nothing here touches Magnus's own build.

## What was run

1. Built the reference `osslserver`/`osslclient` pair from ngtcp2's own
   `examples/` (the same source the "Recommendation" in the evaluation
   doc is based on), linked against the EPEL `libngtcp2`/
   `libngtcp2_crypto_ossl` and the source-built `nghttp3`.
2. Generated a throwaway self-signed EC (P-256) certificate.
3. Started `osslserver` on `127.0.0.1:4433` with a one-file document
   root.
4. Ran `osslclient` against it twice, independently (`--exit-on-all-
   streams-close` each time), each doing a full QUIC v1 handshake
   followed by one HTTP/3 GET.

## Result

Both runs: QUIC handshake confirmed, HTTP/3 response `:status: 200`,
`content-length: 44`, body byte-for-byte the file placed on the server.
Example (first run):

```
QUIC handshake has been confirmed
...
http: stream 0x0 [:status: 200]
http: stream 0x0 [server: nghttp3/ngtcp2 server]
http: stream 0x0 [content-type: text/html]
http: stream 0x0 [content-length: 44]
http: stream 0x0 body 44 bytes
magnus-phase4-spike-ok 2026-08-22T00:17:50Z
```

Both connections closed cleanly (`HANDSHAKE_DONE`, a graceful
`CONNECTION_CLOSE` with H3 `NO_ERROR` shown as `error_code=(unknown)
(0x100)` in ngtcp2's own log formatting, then the QUIC draining period
completing normally). No crash, no hang, no unexpected error line in
either process's log across both connections. The server process stayed
alive and reused cleanly between the two independent client runs.

Not done in this spike (out of scope for item 1, or requiring the real
Phase 4 integration to test meaningfully):

- ASan/UBSan instrumentation of this specific build (Magnus's own Phase
  4 code gets that per Section 7's test plan once it exists; the
  reference examples are upstream-maintained code, not Magnus's own
  attack surface)
- Whether OpenSSL's "keep crypto data intact until told otherwise"
  constraint is compatible with Magnus's own per-connection buffer
  reuse — the reference client/server manage their own buffers, not
  Magnus's, so this only gets answered once Magnus's own event loop is
  the one holding those buffers

## Conclusion

This settles the part of item 1 that could be settled from outside
`src/`: ngtcp2 1.19.0 + `libngtcp2_crypto_ossl` + nghttp3 1.19.0 is not
a dead end against a real, current (3.5.5) OpenSSL — a real handshake
and HTTP/3 round trip completes cleanly, repeatably, with the exact
version floor (`libngtcp2_crypto_ossl` needs ngtcp2 ≥ 1.12.0; EPEL ships
1.19.0) the evaluation doc called out. The recommendation in
`docs/phase4-http3-quic-dependency-evaluation.md` stands. The
buffer-lifetime question against Magnus's own model remains open and is
the first thing Phase 4 implementation work should probe, in isolation,
before wiring QUIC into the rest of `magnus.c`.
