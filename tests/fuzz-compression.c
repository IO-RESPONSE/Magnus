/* Mutation-based fuzz driver for magnus_negotiate_encoding() (roadmap
 * 2a-6, extending 2a-5; magnus_accepts_gzip() before either) -- it
 * parses the client-supplied Accept-Encoding request header directly,
 * so it gets the
 * same fuzzing treatment as every other new parser of untrusted bytes
 * this project has added (see e.g. tests/fuzz-base64.c, roadmap 1e-5).
 * Same approach as every other fuzz-*.c in this codebase: a small seed
 * corpus, seeded/deterministic mutation, crash (or an ASan/UBSan finding
 * under `make sanitize`) is the only failure mode this program cares
 * about -- it does not re-check correctness, that is
 * tests/test-compression.c's job. */

#include "magnus_compression.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_LENGTH 128

static const char magnus_fuzz_seeds[][48] = {
    "",
    "gzip",
    "GZip",
    "gzip;q=0",
    "zstd",
    "ZStd",
    "zstd;q=0",
    "zstd, gzip",
    "gzip, zstd",
    "br",
    "Br",
    "br;q=0",
    "brotli",
    "gzip, br",
    "br, gzip ; q=0.5, deflate",
    "br, zstd; q=0.5, deflate",
    "zstd, br, gzip",
    "br, xgzip, xzstd, deflate",
    "identity",
    "*",
    "gzip,gzip,gzip",
    ";;;",
    "gzip;;;;;;",
    ",,,,gzip,,,,",
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
            buffer[index] = (char) (magnus_fuzz_rand() % 256);
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
        size_t seed_count = sizeof(magnus_fuzz_seeds) / sizeof(magnus_fuzz_seeds[0]);
        size_t seed_index = magnus_fuzz_rand() % seed_count;
        size_t length = strlen(magnus_fuzz_seeds[seed_index]);
        unsigned mutations = 1 + (magnus_fuzz_rand() % 6);

        memcpy(buffer, magnus_fuzz_seeds[seed_index], length);
        for (unsigned m = 0; m < mutations; m++)
            magnus_fuzz_mutate(buffer, &length, sizeof(buffer) - 1);
        buffer[length] = '\0';

        (void) magnus_negotiate_encoding(buffer);
        (void) magnus_content_type_compressible(buffer);
    }

    printf("fuzz-compression: %lu iterations, no crash (seed=%u)\n",
           iterations, magnus_fuzz_state);
    return 0;
}
