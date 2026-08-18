# syntax=docker/dockerfile:1
ARG BUILDER_IMAGE=debian:13-slim
ARG BASE_IMAGE=ioresponse/glibc71-base:poc

FROM ${BUILDER_IMAGE} AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make clean all \
    && strip --strip-unneeded build/magnus \
    && mkdir -p /out/usr/sbin /out/lib64 \
    && cp build/magnus /out/usr/sbin/magnus \
    && cp -L /usr/lib/x86_64-linux-gnu/libssl.so.3 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libz.so.1 /out/lib64/ \
    && cp -L /usr/lib/x86_64-linux-gnu/libzstd.so.1 /out/lib64/

FROM ${BASE_IMAGE}
COPY --from=builder /out/ /
LABEL org.opencontainers.image.title="Magnus Web Engine" \
      org.opencontainers.image.vendor="IORESPONSE" \
      org.opencontainers.image.version="0.2.0-dev" \
      net.ioresponse.magnus.engine="native-c17-epoll" \
      net.ioresponse.magnus.base="micro-linux-glibc-2.44"
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
  CMD ["/usr/bin/wget", "-q", "-O", "-", "http://127.0.0.1:8080/healthz"]
USER 65534:65534
ENTRYPOINT ["/usr/sbin/magnus"]
CMD ["--port", "8080"]
