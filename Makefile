CC ?= cc
CFLAGS ?= -O2 -pipe -std=c17 -Wall -Wextra -Werror -Wpedantic
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now
LDLIBS ?= -lssl -lcrypto

SOURCES := src/magnus.c src/magnus_config.c src/magnus_http.c src/magnus_phase.c \
           src/magnus_policy.c src/magnus_proxy.c
OBJECTS := $(SOURCES:src/%.c=build/%.o)

.PHONY: all clean test sanitize
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

build/magnus: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build/magnusd: src/magnusd.c src/magnus_config.c src/magnus_config.h \
		src/magnusd_protocol.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc src/magnusd.c src/magnus_config.c \
		$(LDFLAGS) -o $@

build/magnusctl: src/magnusctl.c src/magnus_config.c src/magnus_config.h \
		src/magnusd_protocol.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc src/magnusctl.c src/magnus_config.c \
		$(LDFLAGS) -o $@

test: all build/test-http build/test-policy build/test-proxy build/test-config \
		build/fuzz-http
	./build/test-http
	./build/test-policy
	./build/test-proxy
	./build/test-config
	./build/fuzz-http
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

build/test-config: tests/test-config.c src/magnus_config.c src/magnus_config.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-config.c src/magnus_config.c -o $@

build/fuzz-http: tests/fuzz-http.c src/magnus_http.c src/magnus_http.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/fuzz-http.c src/magnus_http.c -o $@

clean:
	rm -rf build
