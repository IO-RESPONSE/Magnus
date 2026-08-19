/* Exercises magnus_dns.c end-to-end (real worker thread, real eventfd,
 * real getaddrinfo() against the environment's own resolver
 * configuration) rather than mocking any of it -- the thing actually
 * worth verifying here is the cross-thread plumbing (request queue,
 * result queue, eventfd wakeup), which a mock would sidestep entirely. */

#include "magnus_dns.h"

#include <assert.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    magnus_dns_result_t results[8];
    size_t count;
} collected_t;

static void
collect(const magnus_dns_result_t *result, void *data)
{
    collected_t *collected = data;
    if (collected->count < 8) collected->results[collected->count++] = *result;
}

static void
wait_for_eventfd(int fd, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);
    assert(rc == 1);
}

int
main(void)
{
    int fd = magnus_dns_start();
    assert(fd >= 0);

    /* A second magnus_dns_start() without an intervening stop() must
     * fail cleanly, not double-spawn a worker or corrupt state. */
    assert(magnus_dns_start() == -1);

    /* localhost resolves via /etc/hosts on essentially any POSIX system,
     * no network round-trip required -- keeps this test fast and not
     * dependent on outbound DNS actually working in whatever environment
     * runs it. */
    magnus_dns_resolve("localhost", 42);
    wait_for_eventfd(fd, 5000);
    {
        collected_t collected = {0};
        magnus_dns_drain_results(collect, &collected);
        assert(collected.count == 1);
        assert(collected.results[0].token == 42);
        assert(collected.results[0].ok);
        assert(strlen(collected.results[0].address) > 0);
        printf("localhost -> %s\n", collected.results[0].address);
    }

    /* A name that cannot resolve reports failure, not a crash or a hang,
     * and does not wedge the worker for the next (valid) request. */
    magnus_dns_resolve("this-name-should-not-resolve.invalid", 7);
    wait_for_eventfd(fd, 5000);
    {
        collected_t collected = {0};
        magnus_dns_drain_results(collect, &collected);
        assert(collected.count == 1);
        assert(collected.results[0].token == 7);
        assert(!collected.results[0].ok);
        assert(collected.results[0].address[0] == '\0');
    }

    /* Several requests queued back-to-back all come back, each carrying
     * its own token back correctly (order is not guaranteed to be
     * request order under concurrency, so match by token instead). */
    magnus_dns_resolve("localhost", 1);
    magnus_dns_resolve("localhost", 2);
    magnus_dns_resolve("localhost", 3);
    {
        collected_t collected = {0};
        while (collected.count < 3) {
            wait_for_eventfd(fd, 5000);
            magnus_dns_drain_results(collect, &collected);
        }
        bool seen[4] = {0};
        for (size_t i = 0; i < collected.count; i++) {
            assert(collected.results[i].ok);
            seen[collected.results[i].token] = true;
        }
        assert(seen[1] && seen[2] && seen[3]);
    }

    magnus_dns_stop();
    /* Idempotent: stopping an already-stopped resolver must not crash. */
    magnus_dns_stop();

    /* A fresh start()/resolve()/stop() cycle after a stop() must work --
     * the module is not a use-once singleton. */
    fd = magnus_dns_start();
    assert(fd >= 0);
    magnus_dns_resolve("localhost", 99);
    wait_for_eventfd(fd, 5000);
    {
        collected_t collected = {0};
        magnus_dns_drain_results(collect, &collected);
        assert(collected.count == 1);
        assert(collected.results[0].token == 99);
        assert(collected.results[0].ok);
    }
    magnus_dns_stop();

    printf("test-dns: ok\n");
    return 0;
}
