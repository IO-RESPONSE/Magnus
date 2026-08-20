/* Mutation-based fuzz driver for magnus_h2_alpn_select_callback()'s
 * client-protocol-list scanning -- attacker-controlled bytes (an ALPN
 * extension is client-supplied), unlike magnus_h2_configure_alpn()
 * itself, which just registers the callback once at startup/reload and
 * has nothing to fuzz. Same approach as every other fuzz-*.c in this
 * codebase: a small seed corpus, seeded/deterministic mutation, crash
 * (or an ASan/UBSan finding under `make sanitize`) is the only failure
 * mode this program cares about. */

#include "magnus_h2.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_LENGTH 64

static const unsigned char magnus_fuzz_seeds[][12] = {
    {2, 'h', '2'},
    {8, 'h','t','t','p','/','1','.','1'},
    {8, 'h','t','t','p','/','1','.','1', 2, 'h', '2'},
    {0},
    {200, 'h', '2'},
    {0, 2, 'h', '2'},
    {3, 'x', 'h', '2', 2, 'h', '2'},
};
static const size_t magnus_fuzz_seed_lengths[] = {3, 9, 11, 0, 3, 4, 7};

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
magnus_fuzz_mutate(unsigned char *buffer, size_t *length, size_t capacity)
{
    unsigned operation = magnus_fuzz_rand() % 5;
    switch (operation) {
    case 0:
        if (*length > 0) {
            size_t index = magnus_fuzz_rand() % *length;
            buffer[index] = (unsigned char) (magnus_fuzz_rand() % 256);
        }
        break;
    case 1:
        if (*length + 1 < capacity) {
            size_t index = magnus_fuzz_rand() % (*length + 1);
            memmove(buffer + index + 1, buffer + index, *length - index);
            buffer[index] = (unsigned char) (magnus_fuzz_rand() % 256);
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
    unsigned char buffer[MAGNUS_FUZZ_MAX_LENGTH];
    const char *seed_env = getenv("MAGNUS_FUZZ_SEED");
    unsigned long iterations;
    const char *iterations_env = getenv("MAGNUS_FUZZ_ITERATIONS");

    magnus_fuzz_state = seed_env != NULL ? (uint32_t) strtoul(seed_env, NULL, 10)
                                         : 0xbb67ae85u;
    if (magnus_fuzz_state == 0) magnus_fuzz_state = 1;
    iterations = iterations_env != NULL
        ? strtoul(iterations_env, NULL, 10) : MAGNUS_FUZZ_ITERATIONS;

    for (unsigned long iteration = 0; iteration < iterations; iteration++) {
        size_t seed_count = sizeof(magnus_fuzz_seeds) / sizeof(magnus_fuzz_seeds[0]);
        size_t seed_index = magnus_fuzz_rand() % seed_count;
        size_t length = magnus_fuzz_seed_lengths[seed_index];
        unsigned mutations = 1 + (magnus_fuzz_rand() % 6);
        const unsigned char *out;
        unsigned char outlen;

        if (length >= sizeof(buffer)) length = sizeof(buffer) - 1;
        memcpy(buffer, magnus_fuzz_seeds[seed_index], length);
        for (unsigned m = 0; m < mutations; m++)
            magnus_fuzz_mutate(buffer, &length, sizeof(buffer));

        (void) magnus_h2_alpn_select_callback(NULL, &out, &outlen, buffer,
                                              (unsigned int) length, NULL);
    }

    printf("fuzz-h2: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
