/* Mutation-based fuzz driver for magnus_ws_parse_header() -- same
 * approach as tests/fuzz-http.c and tests/fuzz-route.c: a corpus of
 * valid-ish frame headers, mutated by a seeded PRNG across many
 * iterations, fed straight to the parser. MAGNUS_WS_HEADER_INVALID (or
 * _INCOMPLETE) is a correct, expected outcome for malformed/truncated
 * input; the only failure this program cares about is the parser
 * crashing or (under `make sanitize`) ASan/UBSan firing -- especially
 * relevant here given the extended-length paths read up to 8 more bytes
 * conditionally on what the first two said. */

#include "magnus_ws.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_LENGTH 32

static const unsigned char magnus_fuzz_seeds[][10] = {
    {0x81, 0x05},                                                 /* text, 5B, unmasked */
    {0x82, 0x85, 0xAA, 0xBB, 0xCC, 0xDD},                         /* binary, 5B, masked */
    {0x82, 0x7E, 0x00, 0xC8},                                     /* binary, 16-bit len */
    {0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xA0}, /* binary, 64-bit len */
    {0x88, 0x02, 0x03, 0xE8},                                     /* close, status code */
    {0x89, 0x00},                                                 /* ping, empty */
    {0x8A, 0x80, 0x00, 0x00, 0x00, 0x00},                         /* pong, masked, empty */
    {0x00, 0x05},                                                 /* continuation */
    {0xF1, 0x00},                                                 /* reserved bits set */
    {0},                                                           /* empty */
};
static const size_t magnus_fuzz_seed_lengths[] = {2, 6, 4, 10, 4, 2, 6, 2, 2, 0};

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
            buffer[index] ^= (unsigned char) (1u << (magnus_fuzz_rand() % 8));
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
                                         : 0x6a09e667u;
    if (magnus_fuzz_state == 0) magnus_fuzz_state = 1;
    iterations = iterations_env != NULL
        ? strtoul(iterations_env, NULL, 10) : MAGNUS_FUZZ_ITERATIONS;

    for (unsigned long iteration = 0; iteration < iterations; iteration++) {
        size_t seed_count = sizeof(magnus_fuzz_seeds) / sizeof(magnus_fuzz_seeds[0]);
        size_t seed_index = magnus_fuzz_rand() % seed_count;
        size_t length = magnus_fuzz_seed_lengths[seed_index];
        magnus_ws_frame_header_t header;
        unsigned mutations = 1 + (magnus_fuzz_rand() % 6);

        if (length >= sizeof(buffer)) length = sizeof(buffer) - 1;
        memcpy(buffer, magnus_fuzz_seeds[seed_index], length);
        for (unsigned m = 0; m < mutations; m++)
            magnus_fuzz_mutate(buffer, &length, sizeof(buffer));

        /* The real target: must never crash or (under ASan/UBSan) read
         * out of bounds, regardless of what it decides about validity,
         * including every partial-length-present truncation this loop
         * can produce along the way. */
        magnus_ws_header_result_t result
            = magnus_ws_parse_header(buffer, length, &header);
        if (result == MAGNUS_WS_HEADER_OK) {
            (void) magnus_ws_mask_direction_ok(&header, true);
            (void) magnus_ws_mask_direction_ok(&header, false);
        }
    }

    printf("fuzz-ws: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
