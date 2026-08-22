# Third-party notices

Magnus's data plane is an independent C17/epoll engine and does not link
against or embed any third-party HTTP server. The runtime image bundles the
following third-party shared libraries, unmodified, from their upstream
distributions:

## OpenSSL

- Upstream: https://github.com/openssl/openssl
- License: Apache License 2.0
- Used for: TLS 1.2/1.3 transport (`libssl`, `libcrypto`)

## zlib

- Upstream: https://zlib.net
- License: zlib License
- Used for: gzip static-response compression and as a TLS-stack dependency
  (`libz`)

## Zstandard

- Upstream: https://github.com/facebook/zstd
- License: BSD 3-Clause License
- Used for: transitive dependency of the TLS stack (`libzstd`)

## ngtcp2 / ngtcp2_crypto_ossl

- Upstream: https://github.com/ngtcp2/ngtcp2
- License: MIT License
- Used for: QUIC transport (RFC 9000) and its OpenSSL-3.5+ crypto backend
  (`libngtcp2`, `libngtcp2_crypto_ossl`) -- see
  `docs/phase4-http3-quic-dependency-evaluation.md` for why this stack was
  chosen and `docs/phase4-spike-results.md` for it verified working.

## nghttp3

- Upstream: https://github.com/ngtcp2/nghttp3
- License: MIT License
- Used for: HTTP/3 framing and QPACK (RFC 9114) over the QUIC transport
  above (`libnghttp3`) -- static-file GET/HEAD only in this release
  (roadmap Phase 4b, see `src/magnus_quic.h`); no proxy dispatch or
  compression over HTTP/3 yet.

Each component's upstream license and copyright notice must be preserved
unchanged in every distribution that bundles the corresponding library.
