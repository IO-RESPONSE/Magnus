/* Mutation-based fuzz driver for src/magnus_fastcgi.c's own parsers --
 * roadmap Phase 6's first increment (a cross-cutting security pass now
 * that every protocol surface Phase 1-5 planned actually exists):
 * magnus_fastcgi_read_header() (the 8-byte binary record header) and
 * magnus_fastcgi_find_body()/magnus_fastcgi_translate_headers() (the
 * CGI-shaped response body -- an application server, or SCGI's own
 * reuse of this exact same translation function, is genuinely
 * untrusted-adjacent input from this codebase's own trust boundary:
 * whatever a compromised or simply buggy upstream application server
 * sends back). This closes a real gap -- every *other* parser this
 * codebase added across Phase 1-5 got its own fuzz target the moment
 * it was written (this file's own top comment on every sibling fuzz-*
 * target already documents that convention), but FastCGI/SCGI/uwsgi
 * dispatch (5a/5b/5c) shipped without one. Same seeded, deterministic,
 * crash/ASan-UBSan-finding-only failure mode as every sibling target. */

#include "magnus_fastcgi.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_LENGTH 512

/* CGI-shaped response bodies for find_body()/translate_headers(). */
static const char *const magnus_fuzz_response_seeds[] = {
    "Content-Type: text/html\r\n\r\n<html></html>",
    "Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnope\n",
    "Status: 201\r\n\r\n",
    "Status: not-a-number\r\nX-App: yes\r\n\r\nbody",
    "\n\n",
    "\r\n\r\n",
    "",
    "no-blank-line-at-all-just-content",
    "Content-Type: text/html\n\n<html></html>",           /* bare LF */
    "Status: 200 OK\r\nStatus: 201 Created\r\n\r\n",       /* dup header */
    "X-App: yes\r\nConnection: keep-alive\r\nContent-Length: 999\r\n\r\nbody",
    "Set-Cookie: a=b\r\n\r\n",
    "Status: 999999999999999999999999\r\n\r\n",           /* overflow */
    "Status:\r\n\r\n",
    "Status:200\r\n\r\n",                                  /* no space */
    ":\r\n\r\n",                                            /* empty name */
    "\r\n\r\n\r\n\r\n",
};

/* 8-byte record headers for read_header(). */
static const unsigned char magnus_fuzz_header_seeds[][MAGNUS_FASTCGI_HEADER_LEN] = {
    { 1, 6, 0, 1, 0xff, 0xff, 0, 0 },   /* STDOUT, max content length */
    { 1, 3, 0, 1, 0, 0, 0, 0 },         /* END_REQUEST, empty */
    { 9, 6, 0, 1, 0, 0, 0, 0 },         /* bad version */
    { 1, 255, 0xff, 0xff, 0xff, 0xff, 0xff, 0 }, /* garbage type/id/length */
    { 0, 0, 0, 0, 0, 0, 0, 0 },
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
        /* Half the iterations exercise the response-header parser
         * (find_body + translate_headers together, the real end-to-end
         * path magnus.c's own dispatch code always calls them as), the
         * other half the binary record-header decoder -- two
         * genuinely different input shapes, same harness. */
        if (iteration % 2 == 0) {
            size_t seed_index = magnus_fuzz_rand() % (sizeof(magnus_fuzz_response_seeds)
                / sizeof(magnus_fuzz_response_seeds[0]));
            size_t length = strlen(magnus_fuzz_response_seeds[seed_index]);
            unsigned mutations = 1 + (magnus_fuzz_rand() % 6);
            const char *body;
            size_t header_text_length;
            char out[8192];
            /* Also fuzz the output capacity itself -- exercises the
             * "too small, must fail cleanly rather than overflow"
             * path, the same reasoning tests/test-fastcgi.c's own
             * dedicated small-buffer unit test already covers once,
             * fuzzed here across many more shapes. */
            size_t out_capacity = 8 + (magnus_fuzz_rand() % sizeof(out));
            unsigned status = 0;

            if (length >= sizeof(buffer)) length = sizeof(buffer) - 1;
            memcpy(buffer, magnus_fuzz_response_seeds[seed_index], length);
            for (unsigned m = 0; m < mutations; m++)
                magnus_fuzz_mutate(buffer, &length, sizeof(buffer));

            body = magnus_fastcgi_find_body(buffer, length, &header_text_length);
            if (body != NULL) {
                size_t body_length = length - (size_t) (body - buffer);
                bool close_connection = (magnus_fuzz_rand() % 2) == 0;
                const char *affinity = (magnus_fuzz_rand() % 2) == 0
                    ? NULL : "05-abc123";
                (void) magnus_fastcgi_translate_headers(buffer,
                    header_text_length, body_length, close_connection,
                    affinity, "magnus-fuzz/0.1", out, out_capacity, &status);
            }
        } else {
            unsigned char header[MAGNUS_FASTCGI_HEADER_LEN];
            size_t seed_index = magnus_fuzz_rand() % (sizeof(magnus_fuzz_header_seeds)
                / sizeof(magnus_fuzz_header_seeds[0]));
            unsigned char type;
            uint16_t request_id;
            size_t content_length;
            unsigned char padding_length;

            memcpy(header, magnus_fuzz_header_seeds[seed_index], sizeof(header));
            /* Byte-level mutation only -- this is a fixed 8-byte
             * structure, not a variable-length buffer, so the same
             * insert/delete/truncate/duplicate operations the other
             * mutator uses would just produce a differently-sized
             * (and therefore meaningless) input; flip a handful of
             * random bits instead. */
            {
                unsigned flips = 1 + (magnus_fuzz_rand() % 4);
                for (unsigned f = 0; f < flips; f++) {
                    size_t index = magnus_fuzz_rand() % sizeof(header);
                    header[index] ^= (unsigned char) (1u << (magnus_fuzz_rand() % 8));
                }
            }
            (void) magnus_fastcgi_read_header(header, &type, &request_id,
                &content_length, &padding_length);
        }
    }

    printf("fuzz-fastcgi: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
