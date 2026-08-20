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

Each component's upstream license and copyright notice must be preserved
unchanged in every distribution that bundles the corresponding library.
