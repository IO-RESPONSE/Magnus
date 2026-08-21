/* Mutation-based fuzz driver for magnus_sni_extract() -- a parser that
 * consumes raw, un-terminated bytes straight off a client socket before
 * any TLS handshake has actually happened (roadmap 3b), the same
 * "peek untrusted bytes, decide, do not crash" shape as
 * magnus_proxy_proto_parse() already gets fuzzed for (fuzz-realip.c).
 * Seeded, deterministic, crash/ASan-UBSan-finding failure mode. */

#include "magnus_sni.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_BUFFER 2048

/* Real/hand-built ClientHello prefixes (see tests/test-sni.c for how
 * they were produced) plus deliberately-adjacent-but-wrong byte
 * sequences -- mutation from a structurally-plausible starting point
 * finds far more real parser bugs than mutating from empty/random noise
 * alone would. */
static const unsigned char magnus_fuzz_sni_seed_with_sni[] = {
    0x16, 0x03, 0x01, 0x00, 0x45, 0x01, 0x00, 0x00, 0x41, 0x03, 0x03, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x12, 0x00, 0x10, 0x00, 0x00,
    0x0d, 0x61, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
    0x6f, 0x6d,
};
static const unsigned char magnus_fuzz_sni_seed_no_sni[] = {
    0x16, 0x03, 0x01, 0x00, 0x2d, 0x01, 0x00, 0x00, 0x29, 0x03, 0x03, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
};
static const unsigned char magnus_fuzz_sni_seed_plain_http[] =
    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
static const unsigned char magnus_fuzz_sni_seed_empty_record[] = {
    0x16, 0x03, 0x01, 0x00, 0x00,
};
static const unsigned char magnus_fuzz_sni_seed_short[] = { 0x16, 0x03 };

static const struct {
    const unsigned char *data;
    size_t length;
} magnus_fuzz_sni_seeds[] = {
    { magnus_fuzz_sni_seed_with_sni, sizeof(magnus_fuzz_sni_seed_with_sni) },
    { magnus_fuzz_sni_seed_no_sni, sizeof(magnus_fuzz_sni_seed_no_sni) },
    { magnus_fuzz_sni_seed_plain_http,
      sizeof(magnus_fuzz_sni_seed_plain_http) - 1 },
    { magnus_fuzz_sni_seed_empty_record,
      sizeof(magnus_fuzz_sni_seed_empty_record) },
    { magnus_fuzz_sni_seed_short, sizeof(magnus_fuzz_sni_seed_short) },
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
magnus_fuzz_mutate(unsigned char *buffer, size_t *length, size_t capacity)
{
    unsigned operation = magnus_fuzz_rand() % 6;
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
    case 5:
        /* Targeted at the length fields themselves -- a purely random
         * byte flip only rarely lands on one of the handful of
         * length-field bytes that actually drive this parser's control
         * flow; deliberately overwriting a 2-byte big-endian field with
         * an extreme value exercises the bounds checks around every
         * length field directly, far more often than chance alone would. */
        if (*length >= 2) {
            size_t index = magnus_fuzz_rand() % (*length - 1);
            uint16_t extreme = (magnus_fuzz_rand() % 2) ? 0xFFFF : 0x0000;
            buffer[index] = (unsigned char) (extreme >> 8);
            buffer[index + 1] = (unsigned char) (extreme & 0xFF);
        }
        break;
    default:
        break;
    }
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
        unsigned char buffer[MAGNUS_FUZZ_MAX_BUFFER];
        size_t seed_index = magnus_fuzz_rand()
            % (sizeof(magnus_fuzz_sni_seeds) / sizeof(magnus_fuzz_sni_seeds[0]));
        size_t length = magnus_fuzz_sni_seeds[seed_index].length;
        char hostname[MAGNUS_SNI_HOSTNAME_MAX];
        unsigned mutations = 1 + (magnus_fuzz_rand() % 6);

        memcpy(buffer, magnus_fuzz_sni_seeds[seed_index].data, length);
        for (unsigned m = 0; m < mutations; m++)
            magnus_fuzz_mutate(buffer, &length, sizeof(buffer));

        (void) magnus_sni_extract(buffer, length, hostname, sizeof(hostname));
        /* Every out_capacity, including ones too small for any real
         * hostname, must still never overflow -- see
         * magnus_sni_extract()'s own bound check on name_length. */
        (void) magnus_sni_extract(buffer, length, hostname,
                                  1 + (magnus_fuzz_rand() % sizeof(hostname)));
    }

    printf("fuzz-sni: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
