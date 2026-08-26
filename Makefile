CC ?= cc
CFLAGS ?= -O2 -pipe -std=c17 -Wall -Wextra -Werror -Wpedantic
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now
# ngtcp2/ngtcp2_crypto_ossl/nghttp3 (Phase 4, roadmap): see
# docs/phase4-http3-quic-dependency-evaluation.md for why this stack and
# docs/phase4-spike-results.md for it verified working against this
# host's OpenSSL. EPEL packages ngtcp2/ngtcp2-crypto-ossl for EL10;
# nghttp3 has no EL package and needs a source build. The Dockerfile's
# own Debian 13 builder needs ngtcp2 built from source too (instead of
# its apt package): Debian's version (1.11.0) is below the >=1.12.0
# floor libngtcp2_crypto_ossl needs for OpenSSL 3.5+ -- see Dockerfile.
# nghttp3 joined this list in 4b (HTTP/3 request/response, src/
# magnus_quic.c) -- 4a linked nothing from it (confirmed via the
# shipped binary's own dynamic dependency list), per Section 5's own
# "record a dependency when it's actually adopted, not before" rule.
# -lzstd joined in 2a-5 (Zstandard response compression,
# src/magnus_compression.c) -- its runtime library was already bundled
# into the Docker image (Dockerfile's own libzstd.so.1 copy predates
# this: a transitive OpenSSL 3.5+ dependency, unused by Magnus's own
# code until now), so this is a build-time-only addition for the image,
# not a new runtime footprint. -lbrotlienc/-lbrotlicommon joined in 2a-6
# (Brotli response compression) -- unlike zstd, this *does* add two new
# runtime libraries to the image (Dockerfile's own new cp -L lines);
# only the encoder is linked, never the decoder (libbrotlidec), since
# Magnus only ever compresses, never decompresses, a response body.
LDLIBS ?= -lssl -lcrypto -lpthread -lnghttp2 -lz -lzstd -lbrotlienc \
          -lbrotlicommon -lngtcp2 -lngtcp2_crypto_ossl -lnghttp3

SOURCES := src/magnus.c src/magnus_base64.c src/magnus_cache.c \
           src/magnus_compression.c \
           src/magnus_config.c src/magnus_dns.c src/magnus_fastcgi.c \
           src/magnus_h2.c \
           src/magnus_http.c src/magnus_phase.c src/magnus_policy.c \
           src/magnus_proxy.c src/magnus_quic.c src/magnus_realip.c \
           src/magnus_route.c src/magnus_scgi.c src/magnus_sni.c \
           src/magnus_uwsgi.c src/magnus_ws.c
OBJECTS := $(SOURCES:src/%.c=build/%.o)

.PHONY: all clean test sanitize tsan
all: build/magnus build/magnusd build/magnusctl

# Full test suite built with ASan+UBSan instead of the normal optimized
# build. Uses its own build/ tree (build-asan) so it never mixes object
# files with a plain `make test` run. Reproduce directly:
#   make clean && make test \
#     CC=cc CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -std=c17 -Wall -Wextra -Wpedantic" \
#     LDFLAGS="-fsanitize=address,undefined"
sanitize:
	$(MAKE) clean
	$(MAKE) test \
		CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -std=c17 -Wall -Wextra -Wpedantic" \
		LDFLAGS="-fsanitize=address,undefined" \
		ASAN_OPTIONS=detect_leaks=1

# ThreadSanitizer, scoped to magnus_dns.c: the only module in this
# codebase with more than one thread ever touching shared state (its own
# request/result queues, behind its own mutex -- the worker thread never
# touches anything outside magnus_dns.c; only the main thread's
# magnus_dns_drain_results() callback reaches into the rest of magnus.c,
# so that boundary is where any race would have to be). ASan/UBSan and
# TSan instrumentation cannot be linked into the same binary, hence a
# separate target rather than folding this into `sanitize`.
tsan:
	mkdir -p build
	$(CC) $(CPPFLAGS) -O0 -g -fsanitize=thread -std=c17 -Wall -Wextra -Wpedantic \
		-Isrc tests/test-dns.c src/magnus_dns.c -fsanitize=thread -lpthread \
		-o build/test-dns-tsan
	./build/test-dns-tsan

build/magnus: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

# Header-dependency tracking for the rule above: without this, editing a
# .h with no matching same-day .c change left `make` reporting "Nothing
# to be done" while a stale .o (compiled against the old struct layout)
# stayed linked into build/magnus -- a real incident, not a hypothetical
# one: magnus_policy.h's magnus_endpoint_t gained a field (TLS-upstream
# support, roadmap 1e-3) while magnus_policy.c itself never mentions TLS
# and so was never touched, and `make` alone did not know to recompile
# it -- silently corrupting every offset src/magnus_policy.c and
# src/magnus.c compute into the shared magnus_cluster_t global relative
# to each other. -MMD -MP emits build/%.d alongside build/%.o listing
# every header a given .c actually pulled in; `-include` below folds
# those back in as extra prerequisites so a header-only edit now forces
# exactly the .o files that need it, same as a .c edit always has.
# Silently ignored (`-include`, not `include`) before any .o has been
# built once to generate a first .d.
-include $(OBJECTS:.o=.d)

build/magnusd: src/magnusd.c src/magnus_config.c src/magnus_config.h \
		src/magnus_route.c src/magnus_http.c src/magnusd_protocol.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc src/magnusd.c src/magnus_config.c \
		src/magnus_route.c src/magnus_http.c $(LDFLAGS) -o $@

build/magnusctl: src/magnusctl.c src/magnus_config.c src/magnus_config.h \
		src/magnus_route.c src/magnus_http.c src/magnusd_protocol.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc src/magnusctl.c src/magnus_config.c \
		src/magnus_route.c src/magnus_http.c $(LDFLAGS) -o $@

test: all build/test-http build/test-policy build/test-proxy build/test-config \
		build/test-route build/test-dns build/test-ws build/test-h2 \
		build/test-base64 build/test-compression build/test-realip \
		build/test-cache build/test-sni build/test-fastcgi build/test-scgi \
		build/test-uwsgi \
		build/quic-handshake-check \
		build/fuzz-http build/fuzz-route build/fuzz-ws build/fuzz-h2 \
		build/fuzz-base64 build/fuzz-compression build/fuzz-realip \
		build/fuzz-sni build/fuzz-fastcgi build/fuzz-scgi build/fuzz-uwsgi
	./build/test-http
	./build/test-policy
	./build/test-proxy
	./build/test-config
	./build/test-route
	./build/test-dns
	./build/test-ws
	./build/test-h2
	./build/test-base64
	./build/test-compression
	./build/test-realip
	./build/test-cache
	./build/test-sni
	./build/test-fastcgi
	./build/test-scgi
	./build/test-uwsgi
	./build/fuzz-http
	./build/fuzz-route
	./build/fuzz-ws
	./build/fuzz-h2
	./build/fuzz-base64
	./build/fuzz-compression
	./build/fuzz-realip
	./build/fuzz-sni
	./build/fuzz-fastcgi
	./build/fuzz-scgi
	./build/fuzz-uwsgi
	./tests/test-core.sh
	./tests/test-control-plane.sh

build/test-http: tests/test-http.c src/magnus_http.c src/magnus_http.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-http.c src/magnus_http.c -o $@

build/test-policy: tests/test-policy.c src/magnus_policy.c src/magnus_policy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-policy.c src/magnus_policy.c -o $@

build/test-proxy: tests/test-proxy.c src/magnus_proxy.c src/magnus_proxy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-proxy.c src/magnus_proxy.c -o $@

build/test-config: tests/test-config.c src/magnus_config.c src/magnus_config.h \
		src/magnus_route.c src/magnus_http.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-config.c src/magnus_config.c \
		src/magnus_route.c src/magnus_http.c -o $@

build/test-route: tests/test-route.c src/magnus_route.c src/magnus_route.h \
		src/magnus_http.c src/magnus_http.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-route.c src/magnus_route.c \
		src/magnus_http.c -o $@

build/test-cache: tests/test-cache.c src/magnus_cache.c src/magnus_cache.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-cache.c src/magnus_cache.c -o $@

build/test-fastcgi: tests/test-fastcgi.c src/magnus_fastcgi.c src/magnus_fastcgi.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-fastcgi.c src/magnus_fastcgi.c -o $@

build/test-scgi: tests/test-scgi.c src/magnus_scgi.c src/magnus_scgi.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-scgi.c src/magnus_scgi.c -o $@

build/test-uwsgi: tests/test-uwsgi.c src/magnus_uwsgi.c src/magnus_uwsgi.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-uwsgi.c src/magnus_uwsgi.c -o $@

build/test-dns: tests/test-dns.c src/magnus_dns.c src/magnus_dns.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-dns.c src/magnus_dns.c \
		-lpthread -o $@

build/fuzz-http: tests/fuzz-http.c src/magnus_http.c src/magnus_http.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-http.c src/magnus_http.c -o $@

build/fuzz-route: tests/fuzz-route.c src/magnus_route.c src/magnus_route.h \
		src/magnus_http.c src/magnus_http.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-route.c src/magnus_route.c \
		src/magnus_http.c -o $@

build/test-ws: tests/test-ws.c src/magnus_ws.c src/magnus_ws.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-ws.c src/magnus_ws.c -o $@

build/fuzz-ws: tests/fuzz-ws.c src/magnus_ws.c src/magnus_ws.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-ws.c src/magnus_ws.c -o $@

build/test-h2: tests/test-h2.c src/magnus_h2.c src/magnus_h2.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-h2.c src/magnus_h2.c \
		-lssl -lcrypto -o $@

build/fuzz-h2: tests/fuzz-h2.c src/magnus_h2.c src/magnus_h2.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-h2.c src/magnus_h2.c \
		-lssl -lcrypto -o $@

build/test-base64: tests/test-base64.c src/magnus_base64.c src/magnus_base64.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-base64.c src/magnus_base64.c -o $@

build/fuzz-base64: tests/fuzz-base64.c src/magnus_base64.c src/magnus_base64.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-base64.c src/magnus_base64.c -o $@

build/test-compression: tests/test-compression.c src/magnus_compression.c \
		src/magnus_compression.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-compression.c \
		src/magnus_compression.c -lz -lzstd -lbrotlienc -lbrotlicommon \
		-lbrotlidec -o $@

build/fuzz-compression: tests/fuzz-compression.c src/magnus_compression.c \
		src/magnus_compression.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-compression.c \
		src/magnus_compression.c -lz -lzstd -lbrotlienc -lbrotlicommon -o $@

build/test-realip: tests/test-realip.c src/magnus_realip.c src/magnus_realip.h \
		src/magnus_route.c src/magnus_http.c src/magnus_config.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-realip.c src/magnus_realip.c \
		src/magnus_route.c src/magnus_http.c -o $@

build/fuzz-realip: tests/fuzz-realip.c src/magnus_realip.c src/magnus_realip.h \
		src/magnus_route.c src/magnus_http.c src/magnus_config.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-realip.c src/magnus_realip.c \
		src/magnus_route.c src/magnus_http.c -o $@

build/test-sni: tests/test-sni.c src/magnus_sni.c src/magnus_sni.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-sni.c src/magnus_sni.c -o $@

build/fuzz-sni: tests/fuzz-sni.c src/magnus_sni.c src/magnus_sni.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-sni.c src/magnus_sni.c -o $@

build/fuzz-fastcgi: tests/fuzz-fastcgi.c src/magnus_fastcgi.c src/magnus_fastcgi.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-fastcgi.c src/magnus_fastcgi.c -o $@

build/fuzz-scgi: tests/fuzz-scgi.c src/magnus_scgi.c src/magnus_scgi.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-scgi.c src/magnus_scgi.c -o $@

build/fuzz-uwsgi: tests/fuzz-uwsgi.c src/magnus_uwsgi.c src/magnus_uwsgi.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-uwsgi.c src/magnus_uwsgi.c -o $@

# Standalone QUIC/HTTP-3 client (Phase 4 regression coverage,
# tests/test-core.sh drives it against a running magnus) -- not a unit
# test binary invoked directly by the `test` target above, same reason
# the Python slowloris/malformed-request helpers inside test-core.sh
# aren't either.
build/quic-handshake-check: tests/quic-handshake-check.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/quic-handshake-check.c $(LDFLAGS) \
		-lssl -lcrypto -lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -o $@

clean:
	rm -rf build
