#ifndef MAGNUS_DNS_H
#define MAGNUS_DNS_H

#include <stdbool.h>
#include <stddef.h>

/* A minimal async DNS client: one dedicated background thread runs the
 * system's own (blocking) getaddrinfo() so the event loop never blocks on
 * a lookup, completion is delivered to the main thread via an eventfd
 * (register it with epoll for EPOLLIN), and requests/results cross the
 * thread boundary through two small mutex-protected ring buffers.
 *
 * Deliberately built on getaddrinfo() rather than a hand-rolled DNS wire
 * parser: it hands correctness (search domains, /etc/hosts, NSS modules,
 * IPv4 selection) to the C library instead of adding a new from-scratch
 * parser of untrusted bytes to this codebase. The trade-off is real and
 * explicit: getaddrinfo()'s standard API does not expose a record's TTL,
 * so callers refresh on a fixed interval, not the name's actual TTL --
 * see MAGNUS_DNS_REFRESH_SECONDS in magnus.c. */

/* Starts the worker thread and its eventfd. Returns the eventfd on
 * success (caller registers it with epoll), or -1 on failure (thread or
 * eventfd creation failed; errno set). Must be called at most once --
 * calling it again without an intervening magnus_dns_stop() returns -1. */
int magnus_dns_start(void);

/* Enqueues an async A-record lookup for `hostname`, tagged with an opaque
 * `token` the matching magnus_dns_result_t carries back unchanged (e.g. a
 * cluster endpoint index) so the caller can tell which request a result
 * belongs to. Non-blocking; safe to call only from the thread that called
 * magnus_dns_start(). If the internal request queue is full, the request
 * is silently dropped -- callers that resolve on a periodic schedule
 * (see magnus_dns_tick() in magnus.c) simply try again next tick. */
void magnus_dns_resolve(const char *hostname, size_t token);

typedef struct {
    size_t token;
    bool ok;
    /* Dotted-decimal IPv4 address, valid only when ok is true. */
    char address[16];
} magnus_dns_result_t;

/* Drains every result ready since the last call (non-blocking) and
 * consumes the eventfd's pending count, calling `callback` once per
 * result in the order they completed. Call this when the eventfd
 * magnus_dns_start() returned reports readable. */
void magnus_dns_drain_results(void (*callback)(const magnus_dns_result_t *result,
                                               void *data), void *data);

/* Signals the worker thread to exit, joins it, and closes the eventfd.
 * Safe to call even if magnus_dns_start() was never called or failed. */
void magnus_dns_stop(void);

#endif
