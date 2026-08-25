#include "magnus_cache.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

struct magnus_cache_entry {
    bool in_use;
    uint64_t hash;
    char host[256];
    char target[256];

    unsigned status;
    char *headers;
    size_t headers_length;
    char *body;
    size_t body_length;
    char etag[128];
    char last_modified[64];

    uint64_t stored_at_ms;
    uint64_t expires_at_ms;

    struct magnus_cache_entry *lru_prev;
    struct magnus_cache_entry *lru_next;
    struct magnus_cache_entry *hash_next;
};

#define MAGNUS_CACHE_HASH_BUCKETS 1024

static magnus_cache_entry_t magnus_cache_slots[MAGNUS_CACHE_MAX_ENTRIES_CEILING];
static magnus_cache_entry_t *magnus_cache_buckets[MAGNUS_CACHE_HASH_BUCKETS];
/* lru_head = most recently used, lru_tail = least (next to evict). */
static magnus_cache_entry_t *magnus_cache_lru_head;
static magnus_cache_entry_t *magnus_cache_lru_tail;
static size_t magnus_cache_used_entries;
static size_t magnus_cache_used_bytes;
static uint64_t magnus_cache_hits;
static uint64_t magnus_cache_misses;
static uint64_t magnus_cache_revalidations;
/* Runtime-effective budget -- see magnus_cache_configure()'s own doc
 * comment in magnus_cache.h. Default to the *_DEFAULT trio so a caller
 * that never calls magnus_cache_configure() at all (every test binary
 * that links this module directly, for one) still gets this codebase's
 * pre-2.1.0 fixed behavior unchanged. */
static size_t magnus_cache_max_entries = MAGNUS_CACHE_MAX_ENTRIES_DEFAULT;
static size_t magnus_cache_max_bytes = MAGNUS_CACHE_MAX_BYTES_DEFAULT;
static size_t magnus_cache_max_entry_bytes = MAGNUS_CACHE_MAX_ENTRY_BYTES_DEFAULT;

void
magnus_cache_configure(size_t max_entries, size_t max_bytes,
                       size_t max_entry_bytes)
{
    magnus_cache_max_entries = max_entries == 0 ? 1
        : (max_entries > MAGNUS_CACHE_MAX_ENTRIES_CEILING
           ? MAGNUS_CACHE_MAX_ENTRIES_CEILING : max_entries);
    magnus_cache_max_bytes = max_bytes > MAGNUS_CACHE_MAX_BYTES_CEILING
        ? MAGNUS_CACHE_MAX_BYTES_CEILING : max_bytes;
    magnus_cache_max_entry_bytes =
        max_entry_bytes > MAGNUS_CACHE_MAX_ENTRY_BYTES_CEILING
        ? MAGNUS_CACHE_MAX_ENTRY_BYTES_CEILING : max_entry_bytes;
}

size_t
magnus_cache_entry_byte_limit(void)
{
    return magnus_cache_max_entry_bytes;
}

uint64_t
magnus_cache_now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t) now.tv_sec * 1000 + (uint64_t) now.tv_nsec / 1000000;
}

static uint64_t
magnus_cache_wall_now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return (uint64_t) now.tv_sec * 1000 + (uint64_t) now.tv_nsec / 1000000;
}

/* FNV-1a, 64-bit -- fast, simple, and this module's only use for it is
 * spreading keys across MAGNUS_CACHE_HASH_BUCKETS buckets; the verbatim
 * host/target comparison in magnus_cache_find() is what actually decides
 * a match, so hash quality only affects lookup speed, never correctness,
 * even in the (unavoidable, with any hash) event of a collision. */
static uint64_t
magnus_cache_hash(const char *host, const char *target)
{
    uint64_t hash = 1469598103934665603ULL;
    const char *p;
    for (p = host; *p != '\0'; p++) {
        hash ^= (unsigned char) *p;
        hash *= 1099511628211ULL;
    }
    hash ^= '\0'; /* separator, so "ab"+"c" cannot collide with "a"+"bc" */
    hash *= 1099511628211ULL;
    for (p = target; *p != '\0'; p++) {
        hash ^= (unsigned char) *p;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void
magnus_cache_lru_unlink(magnus_cache_entry_t *entry)
{
    if (entry->lru_prev != NULL) entry->lru_prev->lru_next = entry->lru_next;
    else magnus_cache_lru_head = entry->lru_next;
    if (entry->lru_next != NULL) entry->lru_next->lru_prev = entry->lru_prev;
    else magnus_cache_lru_tail = entry->lru_prev;
    entry->lru_prev = NULL;
    entry->lru_next = NULL;
}

static void
magnus_cache_lru_push_front(magnus_cache_entry_t *entry)
{
    entry->lru_prev = NULL;
    entry->lru_next = magnus_cache_lru_head;
    if (magnus_cache_lru_head != NULL) magnus_cache_lru_head->lru_prev = entry;
    magnus_cache_lru_head = entry;
    if (magnus_cache_lru_tail == NULL) magnus_cache_lru_tail = entry;
}

static void
magnus_cache_hash_unlink(magnus_cache_entry_t *entry)
{
    magnus_cache_entry_t **slot
        = &magnus_cache_buckets[entry->hash % MAGNUS_CACHE_HASH_BUCKETS];
    while (*slot != NULL) {
        if (*slot == entry) {
            *slot = entry->hash_next;
            entry->hash_next = NULL;
            return;
        }
        slot = &(*slot)->hash_next;
    }
}

static void
magnus_cache_hash_insert(magnus_cache_entry_t *entry)
{
    magnus_cache_entry_t **slot
        = &magnus_cache_buckets[entry->hash % MAGNUS_CACHE_HASH_BUCKETS];
    entry->hash_next = *slot;
    *slot = entry;
}

static magnus_cache_entry_t *
magnus_cache_find(const char *host, const char *target, uint64_t hash)
{
    magnus_cache_entry_t *entry = magnus_cache_buckets[hash % MAGNUS_CACHE_HASH_BUCKETS];
    while (entry != NULL) {
        if (entry->hash == hash && strcmp(entry->host, host) == 0
            && strcmp(entry->target, target) == 0)
            return entry;
        entry = entry->hash_next;
    }
    return NULL;
}

/* Frees an entry's own storage and removes it from both the hash chain
 * and the LRU list, but leaves the slot itself (in_use=false) for reuse
 * -- the shared teardown every eviction/replacement/purge path needs. */
static void
magnus_cache_release(magnus_cache_entry_t *entry)
{
    magnus_cache_hash_unlink(entry);
    magnus_cache_lru_unlink(entry);
    magnus_cache_used_bytes -= entry->headers_length + entry->body_length;
    magnus_cache_used_entries--;
    free(entry->headers);
    free(entry->body);
    entry->headers = NULL;
    entry->body = NULL;
    entry->headers_length = 0;
    entry->body_length = 0;
    entry->in_use = false;
}

/* Evicts the least-recently-used entry to make room. Returns false only
 * if the cache is already empty (nothing left to evict) -- the caller
 * decides what that means (magnus_cache_store() simply gives up). */
static bool
magnus_cache_evict_lru(void)
{
    if (magnus_cache_lru_tail == NULL) return false;
    magnus_cache_release(magnus_cache_lru_tail);
    return true;
}

static magnus_cache_entry_t *
magnus_cache_claim_slot(void)
{
    /* Scans the full physical array (its *_CEILING size), not just the
     * runtime-configured magnus_cache_max_entries -- correct regardless,
     * since magnus_cache_store()'s own eviction loop below already keeps
     * magnus_cache_used_entries under the configured budget before ever
     * reaching this call, so a free slot within that budget always
     * exists somewhere in the full array by the time this runs. */
    for (size_t i = 0; i < MAGNUS_CACHE_MAX_ENTRIES_CEILING; i++) {
        if (!magnus_cache_slots[i].in_use) return &magnus_cache_slots[i];
    }
    return NULL;
}

magnus_cache_entry_t *
magnus_cache_lookup(const char *host, const char *target)
{
    uint64_t hash = magnus_cache_hash(host, target);
    magnus_cache_entry_t *entry = magnus_cache_find(host, target, hash);
    if (entry == NULL) {
        magnus_cache_misses++;
        return NULL;
    }
    magnus_cache_hits++;
    magnus_cache_lru_unlink(entry);
    magnus_cache_lru_push_front(entry);
    return entry;
}

bool
magnus_cache_entry_is_fresh(const magnus_cache_entry_t *entry, uint64_t now_ms)
{
    return now_ms < entry->expires_at_ms;
}

bool
magnus_cache_entry_has_validator(const magnus_cache_entry_t *entry)
{
    return entry->etag[0] != '\0' || entry->last_modified[0] != '\0';
}

unsigned
magnus_cache_entry_status(const magnus_cache_entry_t *entry)
{
    return entry->status;
}

uint64_t
magnus_cache_entry_stored_at_ms(const magnus_cache_entry_t *entry)
{
    return entry->stored_at_ms;
}

void
magnus_cache_entry_data(const magnus_cache_entry_t *entry, const char **headers,
                        size_t *headers_length, const char **body,
                        size_t *body_length, const char **etag,
                        const char **last_modified)
{
    *headers = entry->headers;
    *headers_length = entry->headers_length;
    *body = entry->body;
    *body_length = entry->body_length;
    *etag = entry->etag;
    *last_modified = entry->last_modified;
}

/* Copies `in`/`in_length` into a freshly malloc'd buffer with any
 * "Content-Length:" line removed (case-insensitive; each line is
 * `Name: value\r\n`, matching exactly what
 * magnus_proxy_sanitize_response_headers() and its h2 analogue both
 * produce) -- the stored headers block must never carry the *original*
 * response's own Content-Length, since a future hit replays this same
 * entry's *stored body*, whose length can differ from nothing here at
 * store time but is always recomputed fresh at serve time regardless
 * (simpler and more robust than trusting the two to always agree, and
 * guards every caller uniformly rather than relying on each one to have
 * already excluded it). Returns NULL (leaving `*out_length` untouched) on
 * allocation failure; `*out_length` may end up smaller than `in_length`
 * whether or not a Content-Length line was actually present. */
static char *
magnus_cache_strip_content_length(const char *in, size_t in_length,
                                  size_t *out_length)
{
    char *out = malloc(in_length > 0 ? in_length : 1);
    size_t read_index = 0;
    size_t write_index = 0;
    if (out == NULL) return NULL;
    while (read_index < in_length) {
        size_t line_start = read_index;
        size_t line_length;
        while (read_index + 1 < in_length
               && !(in[read_index] == '\r' && in[read_index + 1] == '\n'))
            read_index++;
        line_length = read_index + 1 < in_length ? read_index + 2 - line_start
                                                  : in_length - line_start;
        if (line_length < strlen("content-length:")
            || strncasecmp(in + line_start, "content-length:",
                           strlen("content-length:")) != 0) {
            memcpy(out + write_index, in + line_start, line_length);
            write_index += line_length;
        }
        read_index = line_start + line_length;
    }
    *out_length = write_index;
    return out;
}

void
magnus_cache_store(const char *host, const char *target, unsigned status,
                   const char *headers_block, size_t headers_block_length,
                   const char *body, size_t body_length, const char *etag,
                   const char *last_modified,
                   const magnus_cache_freshness_t *freshness)
{
    uint64_t hash;
    magnus_cache_entry_t *entry;
    char *headers_copy;
    size_t headers_copy_length;
    char *body_copy = NULL;
    size_t total_bytes;

    if (!freshness->cacheable) return;
    if (strlen(host) >= sizeof(entry->host)
        || strlen(target) >= sizeof(entry->target))
        return;

    headers_copy = magnus_cache_strip_content_length(headers_block,
        headers_block_length, &headers_copy_length);
    if (headers_copy == NULL) return;
    total_bytes = headers_copy_length + body_length;
    if (total_bytes > magnus_cache_max_entry_bytes) {
        free(headers_copy);
        return;
    }

    hash = magnus_cache_hash(host, target);
    entry = magnus_cache_find(host, target, hash);
    if (entry != NULL) {
        /* Replacing an existing entry -- free its old storage first so
         * the byte-budget accounting below starts from this entry
         * contributing zero, not double-counting the stale copy. */
        magnus_cache_used_bytes -= entry->headers_length + entry->body_length;
        free(entry->headers);
        free(entry->body);
        entry->headers = NULL;
        entry->body = NULL;
        magnus_cache_lru_unlink(entry);
    } else {
        while (magnus_cache_used_entries >= magnus_cache_max_entries
               || magnus_cache_used_bytes + total_bytes > magnus_cache_max_bytes) {
            if (!magnus_cache_evict_lru()) break;
        }
        entry = magnus_cache_claim_slot();
        if (entry == NULL) {
            free(headers_copy); /* pathological: every slot in_use but
                                  * eviction still could not free one
                                  * (should not happen -- used_entries is
                                  * kept in lockstep with in_use slots --
                                  * declined defensively) */
            return;
        }
        entry->in_use = true;
        entry->hash = hash;
        strcpy(entry->host, host);
        strcpy(entry->target, target);
        magnus_cache_used_entries++;
        magnus_cache_hash_insert(entry);
    }

    if (body_length > 0) {
        body_copy = malloc(body_length);
        if (body_copy == NULL) {
            free(headers_copy);
            magnus_cache_release(entry);
            return;
        }
        memcpy(body_copy, body, body_length);
    }

    entry->status = status;
    entry->headers = headers_copy;
    entry->headers_length = headers_copy_length;
    entry->body = body_copy;
    entry->body_length = body_length;
    strncpy(entry->etag, etag != NULL ? etag : "", sizeof(entry->etag) - 1);
    entry->etag[sizeof(entry->etag) - 1] = '\0';
    strncpy(entry->last_modified, last_modified != NULL ? last_modified : "",
           sizeof(entry->last_modified) - 1);
    entry->last_modified[sizeof(entry->last_modified) - 1] = '\0';
    entry->stored_at_ms = magnus_cache_now_ms();
    entry->expires_at_ms = freshness->expires_at_ms;
    magnus_cache_used_bytes += headers_copy_length + body_length;
    magnus_cache_lru_push_front(entry);
}

void
magnus_cache_revalidated(magnus_cache_entry_t *entry,
                         const magnus_cache_freshness_t *freshness)
{
    entry->stored_at_ms = magnus_cache_now_ms();
    entry->expires_at_ms = freshness->cacheable ? freshness->expires_at_ms
                                                : entry->stored_at_ms;
    magnus_cache_revalidations++;
}

void
magnus_cache_expire_sweep(uint64_t now_ms)
{
    for (size_t i = 0; i < MAGNUS_CACHE_MAX_ENTRIES_CEILING; i++) {
        magnus_cache_entry_t *entry = &magnus_cache_slots[i];
        if (entry->in_use && now_ms >= entry->expires_at_ms
            && !magnus_cache_entry_has_validator(entry)) {
            /* An expired entry with no validator can never be usefully
             * revalidated (nothing to send as If-None-Match/If-Modified-
             * Since) -- it is a pure miss on every future lookup anyway,
             * so freeing it now is strictly better than waiting for LRU
             * pressure to get around to it. An expired entry that *does*
             * carry a validator is left alone: it is still useful (a
             * revalidation can turn it back into a cheap hit), so only
             * LRU eviction under real memory pressure should reclaim it. */
            magnus_cache_release(entry);
        }
    }
}

void
magnus_cache_purge_all(void)
{
    for (size_t i = 0; i < MAGNUS_CACHE_MAX_ENTRIES_CEILING; i++) {
        if (magnus_cache_slots[i].in_use) magnus_cache_release(&magnus_cache_slots[i]);
    }
}

uint64_t magnus_cache_hits_total(void) { return magnus_cache_hits; }
uint64_t magnus_cache_misses_total(void) { return magnus_cache_misses; }
uint64_t magnus_cache_revalidated_total(void) { return magnus_cache_revalidations; }
size_t magnus_cache_entries_count(void) { return magnus_cache_used_entries; }
size_t magnus_cache_bytes_used(void) { return magnus_cache_used_bytes; }

/* ---- Cache-Control / Expires / Vary parsing ---- */

/* Case-insensitive token match for one Cache-Control directive name at
 * `cursor`, which must be followed by `,`, `=`, whitespace, or the string
 * end (so "no-cache" does not spuriously match a hypothetical "no-cache-
 * extended" directive). */
static bool
magnus_cache_control_token_is(const char *cursor, size_t remaining,
                              const char *name)
{
    size_t name_length = strlen(name);
    if (remaining < name_length) return false;
    if (strncasecmp(cursor, name, name_length) != 0) return false;
    if (remaining == name_length) return true;
    char next = cursor[name_length];
    return next == ',' || next == '=' || next == ' ' || next == '\t';
}

/* Parses a Cache-Control header value's comma-separated directives,
 * looking only for the handful this codebase's cacheability decision
 * actually needs (no-store/no-cache/private/max-age) -- unrecognized
 * directives (public, must-revalidate, s-maxage, immutable, ...) are
 * silently skipped, not rejected: RFC 7234 requires ignoring directives a
 * cache does not understand, not treating them as errors. */
static void
magnus_cache_parse_control(const char *value, bool *no_store, bool *no_cache,
                           bool *private_flag, bool *has_max_age,
                           long *max_age_seconds)
{
    const char *cursor = value;
    *no_store = false;
    *no_cache = false;
    *private_flag = false;
    *has_max_age = false;
    *max_age_seconds = 0;
    if (value == NULL) return;

    while (*cursor != '\0') {
        size_t remaining;
        const char *comma;
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',') cursor++;
        if (*cursor == '\0') break;
        comma = strchr(cursor, ',');
        remaining = comma != NULL ? (size_t) (comma - cursor) : strlen(cursor);

        if (magnus_cache_control_token_is(cursor, remaining, "no-store")) {
            *no_store = true;
        } else if (magnus_cache_control_token_is(cursor, remaining, "no-cache")) {
            *no_cache = true;
        } else if (magnus_cache_control_token_is(cursor, remaining, "private")) {
            *private_flag = true;
        } else if (remaining > 8 && strncasecmp(cursor, "max-age=", 8) == 0) {
            char *end;
            long parsed = strtol(cursor + 8, &end, 10);
            if (end != cursor + 8) {
                *has_max_age = true;
                *max_age_seconds = parsed;
            }
        }
        cursor += remaining;
    }
}

/* Parses an RFC 7231 IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT" -- the
 * only format RFC 7231 permits a sender to generate, though two obsolete
 * ones are still listed for a recipient to accept) into a UTC epoch
 * second count. Tries the two additionally-still-seen obsolete formats
 * (RFC 850 and asctime) as a fallback since accepting them costs nothing
 * and real-world Expires/Last-Modified headers occasionally still use
 * them. Returns false if none match. */
static bool
magnus_cache_parse_http_date(const char *value, time_t *out)
{
    struct tm parsed;
    static const char *const formats[] = {
        "%a, %d %b %Y %H:%M:%S GMT",  /* IMF-fixdate (RFC 7231 preferred) */
        "%A, %d-%b-%y %H:%M:%S GMT",  /* RFC 850 (obsolete) */
        "%a %b %e %H:%M:%S %Y",       /* asctime() (obsolete) */
        NULL,
    };
    for (size_t i = 0; formats[i] != NULL; i++) {
        memset(&parsed, 0, sizeof(parsed));
        if (strptime(value, formats[i], &parsed) != NULL) {
            time_t when = timegm(&parsed);
            if (when != (time_t) -1) {
                *out = when;
                return true;
            }
        }
    }
    return false;
}

/* True if `vary`'s value is either absent/empty, or -- after trimming
 * surrounding whitespace -- case-insensitively exactly "Accept-Encoding".
 * A response Vary-ing on anything else (or on more than one header) is
 * not cacheable in this increment: correctly serving a Vary-keyed cache
 * would mean storing one variant per distinct combination of values the
 * varying header(s) take, real complexity deferred to a future increment
 * (see magnus_cache.h's own top comment). Accept-Encoding is special-
 * cased because this codebase's own upstream request never sends one at
 * all (see magnus_proxy_pick_and_start()'s fixed outbound request) --
 * every cached response is therefore always the identity encoding
 * regardless of what a real client asked for, so a Vary: Accept-Encoding
 * response is exactly as safe to cache as one with no Vary at all. */
static bool
magnus_cache_vary_ok(const char *vary)
{
    const char *start;
    const char *end;
    if (vary == NULL || vary[0] == '\0') return true;
    start = vary;
    while (*start == ' ' || *start == '\t') start++;
    end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
    return (size_t) (end - start) == strlen("accept-encoding")
        && strncasecmp(start, "accept-encoding", (size_t) (end - start)) == 0;
}

void
magnus_cache_compute_freshness(const char *cache_control, const char *expires,
                               const char *vary, bool has_set_cookie,
                               uint64_t now_ms, magnus_cache_freshness_t *out)
{
    bool no_store, no_cache, private_flag, has_max_age;
    long max_age_seconds;

    out->cacheable = false;
    out->expires_at_ms = 0;

    if (has_set_cookie) return;
    if (!magnus_cache_vary_ok(vary)) return;

    magnus_cache_parse_control(cache_control, &no_store, &no_cache,
                               &private_flag, &has_max_age, &max_age_seconds);
    if (no_store || private_flag) return;

    if (has_max_age) {
        long clamped = max_age_seconds < 0 ? 0 : max_age_seconds;
        out->cacheable = true;
        out->expires_at_ms = now_ms + (uint64_t) clamped * 1000;
    } else if (expires != NULL && expires[0] != '\0') {
        time_t when;
        if (!magnus_cache_parse_http_date(expires, &when)) return;
        {
            /* Expires is a wall-clock (CLOCK_REALTIME) deadline, but
             * every *_ms field in this module is on magnus_cache_now_ms()'s
             * CLOCK_MONOTONIC timeline -- the two are not comparable
             * directly (CLOCK_MONOTONIC's own epoch is arbitrary, not
             * 1970-01-01), so the wall-clock deadline is first converted
             * into "how far from wall-clock now" and that same delta is
             * then applied to the monotonic `now_ms` this call already
             * received, landing on the monotonic-timeline equivalent
             * deadline. A negative delta (Expires already in the past --
             * a common "never cache this" idiom some origins use
             * deliberately) is preserved as-is, correctly producing an
             * already-expired entry rather than a wildly wrong one. */
            int64_t expires_wall_ms = (int64_t) when * 1000;
            int64_t now_wall_ms = (int64_t) magnus_cache_wall_now_ms();
            int64_t delta_ms = expires_wall_ms - now_wall_ms;
            out->cacheable = true;
            out->expires_at_ms = (uint64_t) ((int64_t) now_ms + delta_ms);
        }
    }
    /* else: no explicit freshness signal at all -- this increment
     * deliberately does not fall back to heuristic freshness (e.g. a
     * fraction of Last-Modified's own age, the way some caches do), so
     * this stays uncacheable. */

    /* no-cache does not forbid *storing* the response -- it means "never
     * serve this from cache without revalidating first," which this
     * module implements simply by never treating it as fresh: pretending
     * it is already expired, right from the moment it is stored, forces
     * every future hit through the revalidation path instead of a
     * straight serve-from-cache. Still real savings over an outright
     * miss whenever a validator is present (no full body re-fetch), and
     * correct either way. */
    if (out->cacheable && no_cache) out->expires_at_ms = now_ms;
}
