CC ?= cc
CFLAGS ?= -O2 -pipe -std=c17 -Wall -Wextra -Werror -Wpedantic
CPPFLAGS ?= -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now
LDLIBS ?= -lssl -lcrypto

SOURCES := src/magnus.c src/magnus_http.c src/magnus_phase.c src/magnus_policy.c
OBJECTS := $(SOURCES:src/%.c=build/%.o)

.PHONY: all clean test
all: build/magnus

build/magnus: $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

build/%.o: src/%.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test: all build/test-http build/test-policy
	./build/test-http
	./build/test-policy
	./tests/test-core.sh

build/test-http: tests/test-http.c src/magnus_http.c src/magnus_http.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-http.c src/magnus_http.c -o $@

build/test-policy: tests/test-policy.c src/magnus_policy.c src/magnus_policy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc tests/test-policy.c src/magnus_policy.c -o $@

clean:
	rm -rf build
