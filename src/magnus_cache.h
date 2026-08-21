#ifndef MAGNUS_CACHE_H
#define MAGNUS_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Reverse-proxy response cache (roadmap 2d-1): a bounded, in-memory,
 * LRU-evicted store of upstream GET responses for routes that opt in via
 * `action=proxy; cache=on` (magnus_route_t's own `cache_enabled` field,
 * parsed by magnus_route_parse()) -- never applied automatically to every
 * `action=proxy` route, the same opt-in-per-location discipline nginx's
 * own `proxy_cache` directive uses. Caching a response the origin never
 * actually intended to be shared across clients (one that simply forgot
 * to mark itself private/no-store) would be a correctness bug, not just
 * a missed optimization, so this stays an explicit choice per route
 * rather than a global default.
 *
 * Cacheability and freshness follow RFC 7234's core rules, narrowed for a
 * bounded first increment -- see magnus_cache_compute_freshness()'s own
 * comment in magnus_cache.c for the exact rule set and what is
 * deliberately out of scope (heuristic freshness with no explicit
 * Cache-Control/Expires, a shared-cache-specific `s-maxage`, and
 * stale-while-revalidate all stay out). What *is* in scope: an explicit
 * freshness signal (`max-age` or `Expires`), `no-store`/`private`/a
 * response carrying `Set-Cookie` excluded outright (a shared cache must
 * never serve one client's own session state to another), a `Vary` other
 * than (absent or) `Accept-Encoding` excluded (supporting arbitrary Vary
 * dimensions is real complexity, deferred), and conditional-GET
 * revalidation (`If-None-Match`/`If-Modified-Since`) once a stored entry
 * expires but still carries an `ETag`/`Last-Modified` validator. */

/* Fixed capacity/budget -- not currently configurable (matches this
 * codebase's existing precedent: the h1 upstream pool and gRPC connection
 * pool sizes are #define constants too, not config keys). Revisit only if
 * a real deployment needs a different budget than these defaults. */
#define MAGNUS_CACHE_MAX_ENTRIES 512
#define MAGNUS_CACHE_MAX_BYTES (64u * 1024 * 1024)
#define MAGNUS_CACHE_MAX_ENTRY_BYTES (8u * 1024 * 1024)

typedef struct magnus_cache_entry magnus_cache_entry_t;

typedef struct {
    /* False means "do not store this response at all" -- every other
     * field is meaningless when this is false. */
    bool cacheable;
    /* Absolute deadline on magnus_cache_now_ms()'s own monotonic clock
     * (converted from Expires's wall-clock HTTP-date when that is what
     * supplied it -- see magnus_cache_compute_freshness()'s own comment
     * on why that conversion is necessary at all). May already be in the
     * past (an origin can mark something cacheable-but-already-stale on
     * arrival, e.g. via `Expires` in the past combined with `must-
     * revalidate`-like intent) -- storing it anyway is still correct and
     * still saves a full re-fetch once a validator is present, since a
     * stale-with-validator entry revalidates instead of being an outright
     * miss. */
    uint64_t expires_at_ms;
} magnus_cache_freshness_t;

/* Parses an upstream response's Cache-Control/Expires/Vary header values
 * (each NULL or "" if the response did not carry that header) plus
 * whether it carried a Set-Cookie, into a cacheability + freshness
 * verdict. `now_ms` is magnus_cache_now_ms()'s own monotonic clock,
 * anchoring a relative `max-age` into an absolute deadline. */
void magnus_cache_compute_freshness(const char *cache_control,
                                    const char *expires, const char *vary,
                                    bool has_set_cookie, uint64_t now_ms,
                                    magnus_cache_freshness_t *out);

/* This module's own monotonic "now", in milliseconds -- a local twin of
 * magnus.c's own magnus_now_ms() (same CLOCK_MONOTONIC source), needed
 * because this module cannot call across the .c file boundary into a
 * static function. Every *_ms field/parameter in this header is on this
 * clock's timeline. */
uint64_t magnus_cache_now_ms(void);

/* Looks up a stored entry for (host, target) -- exact, case-sensitive
 * match on both (host is whatever the client's own Host header said;
 * target is the raw request-target including any query string, so two
 * URLs differing only in query string are two distinct entries). Returns
 * NULL if nothing is stored. Bumps the entry to the front of the LRU list
 * on any hit, fresh or stale alike -- a stale-but-still-useful-for-
 * revalidation entry is exactly as "recently wanted" as a fresh one. */
magnus_cache_entry_t *magnus_cache_lookup(const char *host,
                                          const char *target);

bool magnus_cache_entry_is_fresh(const magnus_cache_entry_t *entry,
                                 uint64_t now_ms);
bool magnus_cache_entry_has_validator(const magnus_cache_entry_t *entry);
unsigned magnus_cache_entry_status(const magnus_cache_entry_t *entry);
uint64_t magnus_cache_entry_stored_at_ms(const magnus_cache_entry_t *entry);

/* Every pointer/length pair below points directly at the entry's own
 * storage -- valid only until the next call into this module (a lookup
 * or store elsewhere could evict or reallocate this same slot), so a
 * caller must finish copying whatever it needs before yielding back to
 * the event loop. `headers` is the status line followed by pass-through
 * header fields, each CRLF-terminated, with no trailing blank line (the
 * caller appends its own fresh Content-Length/Connection/X-Cache/blank
 * line at serve time -- see magnus_proxy_sanitize_response_headers()'s
 * own `out_cacheable_prefix_length` parameter for where `headers` comes
 * from when storing). `body` is the raw response body, binary-safe (not
 * NUL-terminated, may contain embedded NULs). `etag`/`last_modified` are
 * empty strings ("", never NULL) when that validator was absent. */
void magnus_cache_entry_data(const magnus_cache_entry_t *entry,
                             const char **headers, size_t *headers_length,
                             const char **body, size_t *body_length,
                             const char **etag, const char **last_modified);

/* Stores (or replaces, if one already exists for the same host+target) an
 * entry. No-op -- silently declining to cache, never an error the caller
 * needs to react to -- if `!freshness->cacheable`, if
 * `headers_block_length + body_length` exceeds
 * MAGNUS_CACHE_MAX_ENTRY_BYTES, or on allocation failure: caching is
 * always a pure optimization this codebase can safely decline at any
 * point without affecting correctness. `etag`/`last_modified` may be NULL
 * or "" if that validator was absent from the response. */
void magnus_cache_store(const char *host, const char *target, unsigned status,
                        const char *headers_block, size_t headers_block_length,
                        const char *body, size_t body_length,
                        const char *etag, const char *last_modified,
                        const magnus_cache_freshness_t *freshness);

/* Refreshes an existing entry's freshness window after a successful
 * revalidation (a 304 from the origin) without touching its stored
 * status/headers/body/validators -- the entire point of conditional GET
 * being worth doing at all. If `freshness->cacheable` is false (the 304
 * carried no usable freshness signal of its own), the entry is marked
 * immediately stale again rather than left with its old, already-expired
 * deadline -- still correct (the next hit revalidates again rather than
 * wrongly serving as fresh), and still means the *body* never needed
 * re-fetching. */
void magnus_cache_revalidated(magnus_cache_entry_t *entry,
                              const magnus_cache_freshness_t *freshness);

/* Proactively evicts every entry already past its freshness deadline --
 * cheap memory hygiene (a linear scan over at most MAGNUS_CACHE_MAX_ENTRIES
 * slots), called once per second alongside this codebase's other periodic
 * sweeps. Never required for correctness (magnus_cache_entry_is_fresh()
 * is checked on every lookup regardless) or even for bounding memory
 * (magnus_cache_store()'s own LRU eviction already does that) -- purely
 * so a long-idle entry nothing has revisited since it expired does not
 * sit occupying its slot/budget until something else needs the room. */
void magnus_cache_expire_sweep(uint64_t now_ms);

/* Drops every stored entry immediately. Called on a config reload (a
 * route's own cache=on/off, or the whole route table, may have changed
 * meaning since these entries were stored) and at process shutdown. */
void magnus_cache_purge_all(void);

/* /metrics support. */
uint64_t magnus_cache_hits_total(void);
uint64_t magnus_cache_misses_total(void);
uint64_t magnus_cache_revalidated_total(void);
size_t magnus_cache_entries_count(void);
size_t magnus_cache_bytes_used(void);

#endif
