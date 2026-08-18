/* Mutation-based fuzz driver for magnus_http_parse(): not a libFuzzer/AFL
 * harness (no external toolchain dependency), but the same idea run
 * in-process -- take a corpus of valid-ish requests, mutate them with a
 * seeded PRNG across many iterations, and feed the result straight to the
 * parser. A parse failure (MAGNUS_HTTP_BAD_REQUEST and friends) is a
 * correct, expected outcome for malformed input; the only failure this
 * program cares about is the parser crashing or (under
 * `make sanitize`) ASan/UBSan firing. Run under a plain build for speed
 * during iteration and under `make sanitize` for the real signal.
 *
 * Seeded and deterministic (a fixed seed unless MAGNUS_FUZZ_SEED is set)
 * so a crash is reproducible: rerun with the same seed to get the same
 * mutation sequence. */

#include "magnus_http.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_LENGTH 512

static const char *const magnus_fuzz_seeds[] = {
    "GET / HTTP/1.1\r\nHost: example\r\n\r\n",
    "GET /path?query=1 HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
    "HEAD /x HTTP/1.0\r\n\r\n",
    "POST /submit HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: a\r\nCookie: MAGNUS_AFFINITY=abc; other=1\r\n\r\n",
    "GET /../../etc/passwd HTTP/1.1\r\nHost: a\r\n\r\n",
    "GET / HTTP/1.1\r\n\r\n",
    "",
    "\r\n\r\n",
    "GET",
};

static uint32_t magnus_fuzz_state;

static uint32_t
magnus_fuzz_rand(void)
{
    /* xorshift32 -- fast, seeded, deterministic; not cryptographic and
     * does not need to be. */
    magnus_fuzz_state ^= magnus_fuzz_state << 13;
    magnus_fuzz_state ^= magnus_fuzz_state >> 17;
    magnus_fuzz_state ^= magnus_fuzz_state << 5;
    return magnus_fuzz_state;
}

static void
magnus_fuzz_mutate(char *buffer, size_t *length, size_t capacity)
{
    unsigned operation = magnus_fuzz_rand() % 5;
    switch (operation) {
    case 0: /* flip a random bit in a random byte */
        if (*length > 0) {
            size_t index = magnus_fuzz_rand() % *length;
            buffer[index] ^= (char) (1u << (magnus_fuzz_rand() % 8));
        }
        break;
    case 1: /* insert a random byte */
        if (*length + 1 < capacity) {
            size_t index = magnus_fuzz_rand() % (*length + 1);
            memmove(buffer + index + 1, buffer + index, *length - index);
            buffer[index] = (char) (magnus_fuzz_rand() % 256);
            (*length)++;
        }
        break;
    case 2: /* delete a random byte */
        if (*length > 0) {
            size_t index = magnus_fuzz_rand() % *length;
            memmove(buffer + index, buffer + index + 1, *length - index - 1);
            (*length)--;
        }
        break;
    case 3: /* truncate at a random point */
        if (*length > 0) *length = magnus_fuzz_rand() % *length;
        break;
    case 4: /* duplicate a random slice, growing the buffer */
        if (*length > 0 && *length * 2 < capacity) {
            memcpy(buffer + *length, buffer, *length);
            *length *= 2;
        }
        break;
    default:
        break;
    }
}

int
main(void)
{
    char buffer[MAGNUS_FUZZ_MAX_LENGTH];
    const char *seed_env = getenv("MAGNUS_FUZZ_SEED");
    unsigned long iterations;
    const char *iterations_env = getenv("MAGNUS_FUZZ_ITERATIONS");

    magnus_fuzz_state = seed_env != NULL ? (uint32_t) strtoul(seed_env, NULL, 10)
                                         : 0x9e3779b9u;
    if (magnus_fuzz_state == 0) magnus_fuzz_state = 1; /* xorshift needs nonzero */
    iterations = iterations_env != NULL
        ? strtoul(iterations_env, NULL, 10) : MAGNUS_FUZZ_ITERATIONS;

    for (unsigned long iteration = 0; iteration < iterations; iteration++) {
        size_t seed_index = magnus_fuzz_rand()
            % (sizeof(magnus_fuzz_seeds) / sizeof(magnus_fuzz_seeds[0]));
        size_t length = strlen(magnus_fuzz_seeds[seed_index]);
        magnus_http_request_t request;
        unsigned mutations = 1 + (magnus_fuzz_rand() % 6);

        if (length >= sizeof(buffer)) length = sizeof(buffer) - 1;
        memcpy(buffer, magnus_fuzz_seeds[seed_index], length);
        for (unsigned m = 0; m < mutations; m++)
            magnus_fuzz_mutate(buffer, &length, sizeof(buffer));

        /* The real target: must never crash, hang, or (under ASan/UBSan)
         * read/write out of bounds, regardless of what magnus_http_parse()
         * decides about validity. */
        (void) magnus_http_parse(buffer, length, &request);
    }

    printf("fuzz-http: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
