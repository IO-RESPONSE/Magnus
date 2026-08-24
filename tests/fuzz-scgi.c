/* Mutation-based fuzz driver for src/magnus_scgi.c's own two
 * primitives -- roadmap Phase 6's own cross-cutting fuzz-coverage
 * pass, closing the same gap tests/fuzz-fastcgi.c/fuzz-uwsgi.c do for
 * their own modules. SCGI dispatch's own response side reuses magnus_
 * fastcgi_find_body()/translate_headers() directly (see magnus_scgi.h's
 * own top comment) -- already fuzzed by tests/fuzz-fastcgi.c, nothing
 * new to cover there -- so this harness only needs magnus_scgi_
 * encode_nv() (name/value pair encoding) and magnus_scgi_write_
 * netstring_prefix() (the netstring length-prefix framing), both
 * request-building/output-direction and therefore lower risk than a
 * response parser (their own inputs are this codebase's own already-
 * validated strings, not raw upstream bytes), but cheap to cover
 * regardless -- the same "every parser/encoder gets fuzzed" standard
 * the sibling targets already apply. Same seeded, deterministic,
 * crash/ASan-UBSan-finding-only failure mode. */

#include "magnus_scgi.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAGNUS_FUZZ_ITERATIONS 200000

static uint32_t magnus_fuzz_state;

static uint32_t
magnus_fuzz_rand(void)
{
    magnus_fuzz_state ^= magnus_fuzz_state << 13;
    magnus_fuzz_state ^= magnus_fuzz_state >> 17;
    magnus_fuzz_state ^= magnus_fuzz_state << 5;
    return magnus_fuzz_state;
}

int
main(void)
{
    const char *seed_env = getenv("MAGNUS_FUZZ_SEED");
    unsigned long iterations;
    const char *iterations_env = getenv("MAGNUS_FUZZ_ITERATIONS");

    magnus_fuzz_state = seed_env != NULL ? (uint32_t) strtoul(seed_env, NULL, 10)
                                         : 0x9e3779b9u;
    if (magnus_fuzz_state == 0) magnus_fuzz_state = 1;
    iterations = iterations_env != NULL
        ? strtoul(iterations_env, NULL, 10) : MAGNUS_FUZZ_ITERATIONS;

    for (unsigned long iteration = 0; iteration < iterations; iteration++) {
        if (iteration % 2 == 0) {
            char out[512];
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

            (void) magnus_scgi_encode_nv(name, value, out, out_capacity);
        } else {
            char out[32];
            size_t payload_length = (size_t) magnus_fuzz_rand()
                | ((size_t) magnus_fuzz_rand() << 32);
            size_t out_capacity = magnus_fuzz_rand() % sizeof(out);

            (void) magnus_scgi_write_netstring_prefix(payload_length, out,
                out_capacity);
        }
    }

    printf("fuzz-scgi: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
