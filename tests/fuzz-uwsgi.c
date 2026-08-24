/* Mutation-based fuzz driver for src/magnus_uwsgi.c's own response
 * parser -- roadmap Phase 6's own cross-cutting fuzz-coverage pass,
 * closing the same kind of gap tests/fuzz-fastcgi.c does for that
 * module. magnus_uwsgi_translate_headers() is a genuinely new, hand-
 * written parser (unlike SCGI dispatch, which reuses magnus_fastcgi_
 * translate_headers() as-is -- see magnus_uwsgi.h's own top comment
 * on why a real uWSGI server's response needed its own): it parses a
 * real "HTTP/<version> <status> [reason]" first line rather than a
 * CGI "Status:" line, manual byte-by-byte string scanning this
 * codebase wrote from scratch for this increment specifically, and
 * exactly the kind of hand-rolled parsing logic most worth fuzzing.
 * magnus_uwsgi_encode_var() (the request-building direction) is also
 * covered, lower-risk than the response parser since its own inputs
 * are this codebase's own already-validated strings rather than raw
 * upstream bytes, but cheap to include here regardless. Same seeded,
 * deterministic, crash/ASan-UBSan-finding-only failure mode as every
 * sibling fuzz-* target. */

#include "magnus_uwsgi.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_LENGTH 512

static const char *const magnus_fuzz_response_seeds[] = {
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody",
    "HTTP/1.1 404 Not Found\r\n\r\n",
    "HTTP/1.1 201\r\n\r\n",
    "HTTP/1.1\r\n\r\n",                    /* no status number at all */
    "HTTP/\r\n\r\n",                       /* nothing after HTTP/ */
    "HTTP/1.1 not-a-number ok\r\n\r\n",
    "HTTP/1.1 200 OK",                     /* no blank line at all */
    "HTTP/1.1 999999999999999999 OK\r\n\r\n", /* overflow */
    "HTTP/1.1 099 Weird\r\n\r\n",          /* below 100 */
    "HTTP/1.1 700 TooHigh\r\n\r\n",        /* above 599 */
    "Content-Type: text/plain\r\n\r\nno status line at all",
    "\n\n",
    "\r\n\r\n",
    "",
    "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nbody",  /* bare LF */
    "HTTP/1.1 200 OK\r\nStatus: 500\r\n\r\n", /* Status: header too */
    "HTTP/2 200 OK\r\n\r\n",               /* not "HTTP/<digit>.<digit>" */
};

static uint32_t magnus_fuzz_state;

static uint32_t
magnus_fuzz_rand(void)
{
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
    case 0:
        if (*length > 0) {
            size_t index = magnus_fuzz_rand() % *length;
            buffer[index] ^= (char) (1u << (magnus_fuzz_rand() % 8));
        }
        break;
    case 1:
        if (*length + 1 < capacity) {
            size_t index = magnus_fuzz_rand() % (*length + 1);
            memmove(buffer + index + 1, buffer + index, *length - index);
            buffer[index] = (char) (magnus_fuzz_rand() % 256);
            (*length)++;
        }
        break;
    case 2:
        if (*length > 0) {
            size_t index = magnus_fuzz_rand() % *length;
            memmove(buffer + index, buffer + index + 1, *length - index - 1);
            (*length)--;
        }
        break;
    case 3:
        if (*length > 0) *length = magnus_fuzz_rand() % *length;
        break;
    case 4:
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
    if (magnus_fuzz_state == 0) magnus_fuzz_state = 1;
    iterations = iterations_env != NULL
        ? strtoul(iterations_env, NULL, 10) : MAGNUS_FUZZ_ITERATIONS;

    for (unsigned long iteration = 0; iteration < iterations; iteration++) {
        if (iteration % 4 != 0) {
            /* translate_headers() itself locates its own body offset
             * the same way magnus_uwsgi_finish() (magnus.c) does --
             * via magnus_fastcgi_find_body(), already fuzzed by
             * tests/fuzz-fastcgi.c -- so this harness feeds the whole
             * mutated buffer directly as the header-text argument
             * (header_text_length == length), the same shape every
             * real caller guarantees (find_body() never returns a
             * header_text_length pointing past what was actually
             * received). */
            size_t seed_index = magnus_fuzz_rand() % (sizeof(magnus_fuzz_response_seeds)
                / sizeof(magnus_fuzz_response_seeds[0]));
            size_t length = strlen(magnus_fuzz_response_seeds[seed_index]);
            unsigned mutations = 1 + (magnus_fuzz_rand() % 6);
            char out[8192];
            size_t out_capacity = 8 + (magnus_fuzz_rand() % sizeof(out));
            size_t body_length = magnus_fuzz_rand() % 4096;
            bool close_connection = (magnus_fuzz_rand() % 2) == 0;
            const char *affinity = (magnus_fuzz_rand() % 2) == 0
                ? NULL : "05-abc123";
            unsigned status = 0;

            if (length >= sizeof(buffer)) length = sizeof(buffer) - 1;
            memcpy(buffer, magnus_fuzz_response_seeds[seed_index], length);
            for (unsigned m = 0; m < mutations; m++)
                magnus_fuzz_mutate(buffer, &length, sizeof(buffer));

            (void) magnus_uwsgi_translate_headers(buffer, length, body_length,
                close_connection, affinity, out, out_capacity, &status);
        } else {
            /* encode_var(): name/value pair encoding, output-direction. */
            unsigned char out[512];
            char name[64];
            char value[128];
            size_t name_len = magnus_fuzz_rand() % (sizeof(name) - 1);
            size_t value_len = magnus_fuzz_rand() % (sizeof(value) - 1);
            size_t out_capacity = magnus_fuzz_rand() % sizeof(out);

            for (size_t i = 0; i < name_len; i++)
                name[i] = (char) (1 + (magnus_fuzz_rand() % 255));
            name[name_len] = '\0';
            for (size_t i = 0; i < value_len; i++)
                value[i] = (char) (1 + (magnus_fuzz_rand() % 255));
            value[value_len] = '\0';

            (void) magnus_uwsgi_encode_var(name, value, out, out_capacity);
        }
    }

    printf("fuzz-uwsgi: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
