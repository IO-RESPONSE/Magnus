# syntax=docker/dockerfile:1
ARG BUILDER_IMAGE=debian:13-slim
ARG BASE_IMAGE=ioresponse/glibc71-base:poc

FROM ${BUILDER_IMAGE} AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates \
        libssl-dev libnghttp2-dev zlib1g-dev libzstd-dev libbrotli-dev \
        git autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/*

# ngtcp2 + libngtcp2_crypto_ossl + nghttp3 (Phase 4, roadmap): built
# from source rather than apt, for two independent reasons --
#   - Debian 13 (trixie)'s own ngtcp2 package is 1.11.0, below the
#     >= 1.12.0 floor libngtcp2_crypto_ossl needs to work against
#     OpenSSL 3.5+ (see docs/phase4-http3-quic-dependency-evaluation.md);
#     apt's copy would build but fail this image's own runtime handshake.
#   - nghttp3 has no Debian package at all, in any release.
# ngtcp2 v1.19.0 matches the EPEL version this stack was verified
# against on the development host (docs/phase4-spike-results.md).
# nghttp3 releases its own version numbers independently and lags
# ngtcp2's -- v1.9.0 is its latest actual tag (nghttp3's own upstream
# doc: "any version of ngtcp2 and nghttp3 from v1.0.0 on are expected
# to work" together, so this pairing isn't a compatibility risk).
# --without-libev (and every other crypto backend but openssl, for
# ngtcp2) / --enable-lib-only (for nghttp3) skip what neither this
# image nor Magnus's own build needs. Both installed to /usr/local
# (gcc/ld's own default search path, same as -lssl/-lnghttp2 above
# resolve without any special flag), not layered into the final apt
# package set.
RUN git clone --depth 1 --branch v1.9.0 \
        https://github.com/ngtcp2/nghttp3.git /tmp/nghttp3 \
    && cd /tmp/nghttp3 \
    && git submodule update --init --depth 1 -- lib/sfparse \
    && autoreconf -i \
    && ./configure --prefix=/usr/local --enable-lib-only \
    && make -j"$(nproc)" \
    && make install \
    && git clone --depth 1 --branch v1.19.0 \
        https://github.com/ngtcp2/ngtcp2.git /tmp/ngtcp2 \
    && cd /tmp/ngtcp2 \
    && autoreconf -i \
    && ./configure --prefix=/usr/local --with-openssl --without-gnutls \
        --without-boringssl --without-libev \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /tmp/nghttp3 /tmp/ngtcp2

WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make clean all \
    && strip --strip-unneeded build/magnus build/magnusd \
    && mkdir -p /out/usr/sbin /out/lib64 /out/etc/magnus \
    && cp build/magnus /out/usr/sbin/magnus \
    && cp build/magnusd /out/usr/sbin/magnusd \
    && mkdir -p /out/var/www \
    && printf 'port = 8080\nroot = /var/www\n' > /out/etc/magnus/magnus.conf \
    && cp -L /usr/lib/x86_64-linux-gnu/libssl.so.3 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libz.so.1 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libzstd.so.1 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libbrotlienc.so.1 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libnghttp2.so.14 /out/lib64/ \
    && cp -L /usr/local/lib/libngtcp2.so.16 /out/lib64/ \
    && cp -L /usr/local/lib/libngtcp2_crypto_ossl.so.0 /out/lib64/ \
    && cp -L /usr/local/lib/libnghttp3.so.9 /out/lib64/

FROM ${BASE_IMAGE}
COPY --from=builder /out/ /
LABEL org.opencontainers.image.title="Magnus Web Engine" \
      org.opencontainers.image.vendor="IORESPONSE" \
      org.opencontainers.image.version="2.0.0" \
      net.ioresponse.magnus.engine="native-c17-epoll" \
      net.ioresponse.magnus.base="micro-linux-glibc-2.44"
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
  CMD ["/usr/bin/wget", "-q", "-O", "-", "http://127.0.0.1:8080/healthz"]
USER 65534:65534
# magnusd, not magnus, is PID 1 (roadmap: multi-core worker pool): with
# --workers auto it detects the host's core count and launches that many
# independent magnus workers, each binding port 8080 via SO_REUSEPORT
# within this one container's network namespace -- one container now
# scales across every core the host gives it, instead of the single
# core a bare `magnus` process could ever use. On a single-core host
# (or --workers 1) this degrades to exactly the same one-magnusd/one-
# magnus supervision this image always ran. --socket/--audit-log/
# --rollback-path all point under /tmp (the one writable path under
# this image's read_only root -- see compose.yaml's tmpfs mount)
# because the baked-in /etc/magnus/magnus.conf is not writable: that
# also means SIGHUP-triggered hot-reload's own rollback-on-bad-config
# rewrite (magnusd_reload()) has nowhere to persist against the
# shipped default config -- deployments that need live config reload
# should mount their own writable --config path rather than relying on
# the image's built-in one.
ENTRYPOINT ["/usr/sbin/magnusd"]
CMD ["--config", "/etc/magnus/magnus.conf", "--magnus-binary", "/usr/sbin/magnus", "--socket", "/tmp/magnusd.sock", "--audit-log", "/tmp/magnusd-audit.log", "--rollback-path", "/tmp/magnus.conf.last-good", "--workers", "auto"]
