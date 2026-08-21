CC ?= cc
CFLAGS ?= -O2 -pipe -std=c17 -Wall -Wextra -Werror -Wpedantic
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now
LDLIBS ?= -lssl -lcrypto -lpthread -lnghttp2 -lz

SOURCES := src/magnus.c src/magnus_base64.c src/magnus_cache.c \
           src/magnus_compression.c \
           src/magnus_config.c src/magnus_dns.c src/magnus_h2.c \
           src/magnus_http.c src/magnus_phase.c src/magnus_policy.c \
           src/magnus_proxy.c src/magnus_realip.c src/magnus_route.c \
           src/magnus_ws.c
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
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

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
		build/test-cache \
		build/fuzz-http build/fuzz-route build/fuzz-ws build/fuzz-h2 \
		build/fuzz-base64 build/fuzz-compression build/fuzz-realip
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
	./build/fuzz-http
	./build/fuzz-route
	./build/fuzz-ws
	./build/fuzz-h2
	./build/fuzz-base64
	./build/fuzz-compression
	./build/fuzz-realip
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
		src/magnus_compression.c -lz -o $@

build/fuzz-compression: tests/fuzz-compression.c src/magnus_compression.c \
		src/magnus_compression.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-compression.c \
		src/magnus_compression.c -lz -o $@

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

clean:
	rm -rf build
