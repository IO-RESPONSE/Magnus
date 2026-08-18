CC ?= cc
CFLAGS ?= -O2 -pipe -std=c17 -Wall -Wextra -Werror -Wpedantic
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now
LDLIBS ?= -lssl -lcrypto

SOURCES := src/magnus.c src/magnus_config.c src/magnus_http.c src/magnus_phase.c \
           src/magnus_policy.c src/magnus_proxy.c
OBJECTS := $(SOURCES:src/%.c=build/%.o)

.PHONY: all clean test
all: build/magnus build/magnusd build/magnusctl

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

test: all build/test-http build/test-policy build/test-proxy build/test-config
	./build/test-http
	./build/test-policy
	./build/test-proxy
	./build/test-config
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

clean:
	rm -rf build
