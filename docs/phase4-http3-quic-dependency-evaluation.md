# Phase 4 (HTTP/3/QUIC) — Dependency Evaluation

Per Section 4 and Section 5 of the master prompt, HTTP/3/QUIC is explicitly
**not hand-rolled**: it goes through the dependency framework (Section 22)
before any code, the same gate `docs/development-roadmap.md` applied to
HTTP/2 (nghttp2) in Phase 1e. This document is that gate for Phase 4. It is
an analysis-only deliverable — no Phase 4 source changes are included here,
matching the "review before code" precedent Section 27 already established
for Phase 1.

## 1. Candidates

| Candidate | Language / ABI | License | HTTP/3 layer | TLS/crypto backend | Maintenance signal (checked 2026-08-22) |
|---|---|---|---|---|---|
| **ngtcp2 + nghttp3** | C (C11), C ABI | MIT | nghttp3 (RFC 9114 + QPACK/RFC 9204), separate from the QUIC transport | Pluggable: `libngtcp2_crypto_ossl` (OpenSSL 3.5+, marked *experimental*, needs ngtcp2 ≥ 1.12.0), `libngtcp2_crypto_boringssl` (BoringSSL/aws-lc), `libngtcp2_crypto_quictls` (deprecated), plus libressl/gnutls/picotls/wolfssl backends | ngtcp2 repo updated as recently as 2026-06-30; same author/family as the nghttp2 already adopted for Phase 1e |
| **quiche** (Cloudflare) | Rust core, thin C API (cbindgen) producing a static `libquiche.a` | BSD-2-Clause | Included (QUIC transport + HTTP/3 + qlog in one workspace) | Own (BoringSSL-based, vendored) | Actively maintained; curl still supports it as one of its two remaining HTTP/3 backends as of curl 8.19.0 |
| **msquic** (Microsoft) | C, C ABI | MIT | **Not included** — transport only; would still need nghttp3 (or hand-rolled framing, which Section 4 rules out) paired on top | Own crypto abstraction (OpenSSL or Schannel on Windows) | Actively maintained; v2.5.4 latest stable (2025-08-27), officially supported on Linux, >200 CI build configs per PR |
| **lsquic** (LiteSpeed) | C, C ABI | MIT | Included (QUIC + HTTP/3) | Historically BoringSSL-only; now also builds against vanilla OpenSSL via `LSQUIC_LIBSSL` | Actively maintained; v4.9.2 released 2026-07-27, tracks LiteSpeed's own product line |
| **OpenSSL-native QUIC** (hand-wire directly on `libssl`'s own QUIC API, no ngtcp2/nghttp3) | C | Apache 2.0 (already a Magnus dependency) | Not included — would require writing our own HTTP/3 framing, which Section 4's CVE-history warning explicitly argues against | Itself | OpenSSL 3.5 (2025-04, LTS to 2030) added server-side QUIC; **curl removed its OpenSSL-QUIC backend for curl 8.19.0** (2026-01), citing an API "lacking the controls needed to make it a competitive QUIC alternative" after direct engagement with the OpenSSL QUIC team — ruled out below on the strength of that signal alone |

## 2. Section 2.2 filter (no other language's runtime, unless a leaf C-ABI dependency)

quiche is the one candidate this filter actually has to decide. Its C API
is a genuine C ABI and the build output (`libquiche.a`) is a self-contained
static archive — nothing about *linking* it pulls a Rust runtime into
Magnus's process model (no green-thread scheduler, no async runtime
surfacing across the ABI boundary; quiche's C API is synchronous/poll-driven,
matching Magnus's own single-threaded epoll reactor). What the filter's
"leaf dependency" condition does still cost:

- **Build toolchain**: the *build machine* needs a Rust toolchain (`cargo`)
  in addition to `cc`/`make`, even though the *runtime image* stays
  identical in kind to today (a static library linked into one C binary).
  This is a real change to `Dockerfile`'s build stage and to what a
  from-scratch reproduction of `./scripts/build-image.sh` requires,
  independent of anything shipped at runtime.
- **Supply chain / audit surface**: `libquiche.a` embeds Rust's `std` and
  quiche's own crate dependency tree (not reviewed here) compiled in,
  which `THIRD_PARTY_NOTICES.md` would need to account for as a unit, the
  same way `libzstd` is already listed as a transitive dependency today —
  but with a materially larger and less C-toolchain-legible dependency
  tree than that precedent.

This is a real trade-off, not a disqualification: quiche stays a viable
"leaf dependency with a C ABI" per Section 2.2's own carve-out. It is
weighed below against ngtcp2+nghttp3 rather than ruled out.

## 3. Ruled out before the comparison

- **OpenSSL-native QUIC (hand-rolled HTTP/3 framing on top of it)**: ruled
  out on two independent grounds — Section 4's own warning against
  hand-rolling protocol parsers (the same reasoning that put nghttp2 in
  Phase 1e instead of a hand-rolled HPACK), and curl's own 2026-01 removal
  of its OpenSSL-QUIC backend as not "competitive" after direct engagement
  with the OpenSSL QUIC maintainers. If curl — with far more resources
  applied to exactly this integration — concluded the API isn't there yet,
  re-deriving that conclusion independently isn't a good use of Phase 4's
  budget.
- **msquic**: transport-only. Pairing it with nghttp3 for the HTTP/3 layer
  is possible in principle (nghttp3 "does not depend on any particular QUIC
  transport implementation" by design), but that pairing is far less
  trodden than ngtcp2+nghttp3 (the two are developed together, by the same
  author, explicitly to be paired) or quiche/lsquic (each already a single
  integrated unit). Kept as a fallback note, not carried into the
  head-to-head below.

## 4. Head-to-head: ngtcp2+nghttp3 vs. quiche vs. lsquic

| | ngtcp2 + nghttp3 | quiche | lsquic |
|---|---|---|---|
| Fits existing toolchain unmodified (`cc`, `make`, no new language) | Yes | No — adds `cargo` to the build stage | Yes |
| Crypto backend reuses Magnus's existing OpenSSL 3.5 dependency without a fork | Yes, but only via the *experimental* `libngtcp2_crypto_ossl` backend (ngtcp2 ≥ 1.12.0 required; the "keep crypto data intact until told otherwise" constraint on OpenSSL's QUIC TLS API needs to be checked against Magnus's own buffer-lifetime model before committing) | No — own vendored BoringSSL-based crypto stack, independent of Magnus's `libssl`/`libcrypto` | Historically BoringSSL-only; now also buildable against vanilla OpenSSL, but this path is newer and less battle-tested than lsquic's original BoringSSL path |
| Precedent in this codebase | Same author/toolchain family as nghttp2 (already adopted, Phase 1e) — closest fit to "how Magnus already does this" | None | None |
| HTTP/3 layer included in the same unit | No — nghttp3 is separate (mirrors today's nghttp2 relationship to the rest of Magnus, not a new pattern) | Yes | Yes |
| License | MIT | BSD-2-Clause | MIT |

**Recommendation: ngtcp2 + nghttp3**, on the strength of (a) zero new
build-toolchain language, (b) direct precedent — this is literally the
same relationship Magnus already has with nghttp2 for Phase 1e, extended
by the same author group to QUIC, and (c) an existing-OpenSSL-compatible
crypto path, with its "experimental" label as the one open risk explicitly
flagged below rather than glossed over.

## 5. Open items — not decided by this document, verify before Phase 4 code starts

Per Section 23's prohibition on unverified claims, none of the following
are asserted as settled:

1. **`libngtcp2_crypto_ossl`'s "experimental" status**: needs a standalone
   spike (connect + handshake + one stream, outside the Magnus codebase)
   against the host's actual OpenSSL 3.5.5 before Phase 4 work starts on
   Magnus itself, to find out firsthand whether the buffer-lifetime
   constraint the OpenSSL QUIC TLS API imposes is compatible with Magnus's
   existing per-connection buffer reuse, or whether it forces a design
   change.
2. **Binary size impact**: unmeasured. Current image is ~9 MiB; ngtcp2 +
   nghttp3 need to be built and statically/dynamically linked into a real
   `build-image.sh` run before any size claim is made, the same way the
   nghttp2 Phase 1e entry in `docs/development-roadmap.md` flagged this
   and then measured it rather than guessing.
3. **quiche's dependency tree**: not audited here. If ngtcp2+nghttp3's
   OpenSSL backend turns out to be unworkable in (1), quiche is the
   fallback and its crate tree needs its own `THIRD_PARTY_NOTICES.md`
   pass at that point, not before.
4. **Base image toolchain**: checked, not open. `Dockerfile`'s builder
   stage is `debian:13-slim` (trixie), which packages `openssl`
   3.5.4-1~deb13u2 / 3.5.6-1~deb13u2 depending on point-in-time snapshot —
   either way ≥ 3.5, satisfying `libngtcp2_crypto_ossl`'s floor. No base
   image change needed for item 1's spike.

## 6. Next step if this evaluation is accepted

Item 1's standalone spike, *outside* `src/`, before any change to
`magnus.c`, `Makefile`, or the container build — matching the "prove it
works in isolation first" pattern already used for the Real IP and stream
PROXY-protocol work. Not started by this document.
