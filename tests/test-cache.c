#include "magnus_cache.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int
main(void)
{
    magnus_cache_freshness_t f;
    uint64_t now = magnus_cache_now_ms();

    /* No explicit freshness signal at all -- not cacheable, no heuristic
     * fallback in this increment. */
    magnus_cache_compute_freshness(NULL, NULL, NULL, false, now, &f);
    assert(!f.cacheable);

    /* max-age. */
    magnus_cache_compute_freshness("max-age=60", NULL, NULL, false, now, &f);
    assert(f.cacheable);
    assert(f.expires_at_ms >= now + 59000 && f.expires_at_ms <= now + 61000);

    /* no-store/private/Set-Cookie each override an explicit max-age. */
    magnus_cache_compute_freshness("max-age=60, no-store", NULL, NULL, false,
                                   now, &f);
    assert(!f.cacheable);
    magnus_cache_compute_freshness("private, max-age=60", NULL, NULL, false,
                                   now, &f);
    assert(!f.cacheable);
    magnus_cache_compute_freshness("max-age=60", NULL, NULL, true, now, &f);
    assert(!f.cacheable);

    /* Vary: Accept-Encoding (any case) is fine; any other Vary is not. */
    magnus_cache_compute_freshness("max-age=60", NULL, "Accept-Encoding",
                                   false, now, &f);
    assert(f.cacheable);
    magnus_cache_compute_freshness("max-age=60", NULL, "accept-encoding",
                                   false, now, &f);
    assert(f.cacheable);
    magnus_cache_compute_freshness("max-age=60", NULL, "Cookie", false, now,
                                   &f);
    assert(!f.cacheable);

    /* Expires (future and past), converted from wall-clock to this
     * module's own monotonic timeline. */
    {
        time_t future = time(NULL) + 120;
        struct tm gmt;
        char buf[64];
        gmtime_r(&future, &gmt);
        strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &gmt);
        magnus_cache_compute_freshness(NULL, buf, NULL, false, now, &f);
        assert(f.cacheable);
        assert(f.expires_at_ms > now);
    }
    {
        time_t past = time(NULL) - 120;
        struct tm gmt;
        char buf[64];
        gmtime_r(&past, &gmt);
        strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &gmt);
        magnus_cache_compute_freshness(NULL, buf, NULL, false, now, &f);
        assert(f.cacheable);
        assert(f.expires_at_ms < now);
    }

    /* no-cache still stores, but forces immediate staleness. */
    magnus_cache_compute_freshness("max-age=60, no-cache", NULL, NULL, false,
                                   now, &f);
    assert(f.cacheable);
    assert(f.expires_at_ms <= now);

    /* Store / lookup / serve roundtrip, including per-field integrity. */
    {
        magnus_cache_freshness_t fr;
        magnus_cache_entry_t *e;
        const char *h, *b, *et, *lm;
        size_t hl, bl;

        magnus_cache_compute_freshness("max-age=60", NULL, NULL, false, now,
                                       &fr);
        magnus_cache_store("example.com", "/a", 200, "HTTP/1.1 200 OK\r\n", 18,
                           "hello", 5, "\"etag1\"", NULL, &fr);

        e = magnus_cache_lookup("example.com", "/a");
        assert(e != NULL);
        assert(magnus_cache_entry_is_fresh(e, magnus_cache_now_ms()));
        assert(magnus_cache_entry_has_validator(e));
        assert(magnus_cache_entry_status(e) == 200);
        magnus_cache_entry_data(e, &h, &hl, &b, &bl, &et, &lm);
        assert(hl == 18 && memcmp(h, "HTTP/1.1 200 OK\r\n", 18) == 0);
        assert(bl == 5 && memcmp(b, "hello", 5) == 0);
        assert(strcmp(et, "\"etag1\"") == 0);
        assert(strcmp(lm, "") == 0);

        /* A different host, or a different target, is a distinct key. */
        assert(magnus_cache_lookup("other.com", "/a") == NULL);
        assert(magnus_cache_lookup("example.com", "/b") == NULL);

        assert(magnus_cache_entries_count() == 1);
        assert(magnus_cache_bytes_used() == 18 + 5);

        /* Revalidation refreshes freshness without touching the body. */
        {
            magnus_cache_freshness_t fr2;
            magnus_cache_compute_freshness("max-age=120", NULL, NULL, false,
                                           magnus_cache_now_ms(), &fr2);
            magnus_cache_revalidated(e, &fr2);
            magnus_cache_entry_data(e, &h, &hl, &b, &bl, &et, &lm);
            assert(bl == 5 && memcmp(b, "hello", 5) == 0);
            assert(magnus_cache_entry_is_fresh(e, magnus_cache_now_ms()));
        }

        /* Storing again for the same key replaces in place, not
         * duplicated. */
        magnus_cache_store("example.com", "/a", 200, "HTTP/1.1 200 OK\r\n", 18,
                           "world!", 6, NULL, "Mon, 01 Jan 2024 00:00:00 GMT",
                           &fr);
        e = magnus_cache_lookup("example.com", "/a");
        magnus_cache_entry_data(e, &h, &hl, &b, &bl, &et, &lm);
        assert(bl == 6 && memcmp(b, "world!", 6) == 0);
        assert(strcmp(et, "") == 0);
        assert(strcmp(lm, "Mon, 01 Jan 2024 00:00:00 GMT") == 0);
        assert(magnus_cache_entries_count() == 1);

        magnus_cache_purge_all();
        assert(magnus_cache_entries_count() == 0);
        assert(magnus_cache_bytes_used() == 0);
        assert(magnus_cache_lookup("example.com", "/a") == NULL);
    }

    /* magnus_cache_store() strips any Content-Length line from the
     * headers block it is given -- a stored entry's own Content-Length
     * must always be recomputed fresh from the *stored body*, never
     * replayed from whatever the upstream originally sent (which would
     * risk a duplicate/stale Content-Length once a caller appends its
     * own fresh one at serve time). */
    {
        magnus_cache_freshness_t fr;
        magnus_cache_entry_t *e;
        const char *h, *b, *et, *lm;
        size_t hl, bl;
        const char *raw_headers =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            "Content-Length: 999\r\nX-Custom: yes\r\n";

        magnus_cache_compute_freshness("max-age=60", NULL, NULL, false,
                                       magnus_cache_now_ms(), &fr);
        magnus_cache_store("h", "/cl", 200, raw_headers, strlen(raw_headers),
                           "abc", 3, NULL, NULL, &fr);
        e = magnus_cache_lookup("h", "/cl");
        assert(e != NULL);
        magnus_cache_entry_data(e, &h, &hl, &b, &bl, &et, &lm);
        assert(memmem(h, hl, "Content-Length", 14) == NULL);
        assert(memmem(h, hl, "Content-Type: text/plain", 24) != NULL);
        assert(memmem(h, hl, "X-Custom: yes", 13) != NULL);
        assert(bl == 3 && memcmp(b, "abc", 3) == 0);
        magnus_cache_purge_all();
    }

    /* LRU eviction under entry-count pressure. */
    {
        magnus_cache_freshness_t fr;
        char target[32];
        magnus_cache_compute_freshness("max-age=60", NULL, NULL, false,
                                       magnus_cache_now_ms(), &fr);
        for (int i = 0; i < MAGNUS_CACHE_MAX_ENTRIES_DEFAULT + 10; i++) {
            snprintf(target, sizeof(target), "/t%d", i);
            magnus_cache_store("h", target, 200, "HTTP/1.1 200 OK\r\n", 18,
                               "x", 1, NULL, NULL, &fr);
        }
        assert(magnus_cache_entries_count() == MAGNUS_CACHE_MAX_ENTRIES_DEFAULT);
        assert(magnus_cache_lookup("h", "/t0") == NULL);
        snprintf(target, sizeof(target),
                "/t%d", MAGNUS_CACHE_MAX_ENTRIES_DEFAULT + 9);
        assert(magnus_cache_lookup("h", target) != NULL);
        magnus_cache_purge_all();
    }

    /* Per-entry size cap: an entry over MAGNUS_CACHE_MAX_ENTRY_BYTES_DEFAULT
     * is silently declined, not stored truncated. */
    {
        magnus_cache_freshness_t fr;
        static char oversized[MAGNUS_CACHE_MAX_ENTRY_BYTES_DEFAULT + 1];
        magnus_cache_compute_freshness("max-age=60", NULL, NULL, false,
                                       magnus_cache_now_ms(), &fr);
        magnus_cache_store("h", "/big", 200, "HTTP/1.1 200 OK\r\n", 18,
                           oversized, sizeof(oversized), NULL, NULL, &fr);
        assert(magnus_cache_lookup("h", "/big") == NULL);
    }

    /* Expiry sweep reclaims an expired entry with no validator, but
     * leaves an expired one with a validator alone (still revalidatable). */
    {
        magnus_cache_freshness_t expired;
        expired.cacheable = true;
        expired.expires_at_ms = magnus_cache_now_ms(); /* already due */
        magnus_cache_store("h", "/novalidator", 200, "HTTP/1.1 200 OK\r\n", 18,
                           "x", 1, NULL, NULL, &expired);
        magnus_cache_store("h", "/withvalidator", 200, "HTTP/1.1 200 OK\r\n",
                           18, "x", 1, "\"e\"", NULL, &expired);
        magnus_cache_expire_sweep(magnus_cache_now_ms() + 1);
        assert(magnus_cache_lookup("h", "/novalidator") == NULL);
        assert(magnus_cache_lookup("h", "/withvalidator") != NULL);
        magnus_cache_purge_all();
    }

    /* magnus_cache_configure() (roadmap 2.1.0): a runtime entry-count
     * budget lower than the *_DEFAULT trio above takes effect immediately,
     * clamps a zero max_entries up to 1 rather than making the cache
     * unusable, clamps an over-ceiling request down to the ceiling, and
     * magnus_cache_entry_byte_limit() reflects whatever max_entry_bytes
     * was last configured. Restored to the *_DEFAULT trio afterward so
     * every earlier block above (and any block a future edit adds below)
     * keeps running against this file's original, well-understood
     * defaults. */
    {
        magnus_cache_freshness_t fr;
        char target[32];
        magnus_cache_compute_freshness("max-age=60", NULL, NULL, false,
                                       magnus_cache_now_ms(), &fr);

        magnus_cache_configure(3, MAGNUS_CACHE_MAX_BYTES_DEFAULT, 1024);
        assert(magnus_cache_entry_byte_limit() == 1024);
        for (int i = 0; i < 5; i++) {
            snprintf(target, sizeof(target), "/c%d", i);
            magnus_cache_store("h", target, 200, "HTTP/1.1 200 OK\r\n", 18,
                               "x", 1, NULL, NULL, &fr);
        }
        assert(magnus_cache_entries_count() == 3);
        magnus_cache_purge_all();

        magnus_cache_configure(0, MAGNUS_CACHE_MAX_BYTES_DEFAULT,
                               MAGNUS_CACHE_MAX_ENTRY_BYTES_DEFAULT);
        magnus_cache_store("h", "/z", 200, "HTTP/1.1 200 OK\r\n", 18,
                           "x", 1, NULL, NULL, &fr);
        assert(magnus_cache_entries_count() == 1);
        magnus_cache_purge_all();

        magnus_cache_configure(MAGNUS_CACHE_MAX_ENTRIES_CEILING + 10,
                               MAGNUS_CACHE_MAX_BYTES_CEILING + 10,
                               MAGNUS_CACHE_MAX_ENTRY_BYTES_CEILING + 10);
        assert(magnus_cache_entry_byte_limit()
              == MAGNUS_CACHE_MAX_ENTRY_BYTES_CEILING);

        magnus_cache_configure(MAGNUS_CACHE_MAX_ENTRIES_DEFAULT,
                               MAGNUS_CACHE_MAX_BYTES_DEFAULT,
                               MAGNUS_CACHE_MAX_ENTRY_BYTES_DEFAULT);
    }

    return 0;
}
