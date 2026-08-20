/* Mutation-based fuzz driver for magnus_realip_resolve_headers() and
 * magnus_proxy_proto_parse() -- parsers that consume untrusted header
 * strings and raw socket preamble bytes. Seeded, deterministic,
 * crash/ASan-UBSan-finding failure mode. */

#include "magnus_realip.h"
#include "magnus_config.h"
#include "magnus_http.h"
#include "magnus_route.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_FIELD 512

static const char *const magnus_fuzz_xff_seeds[] = {
    "203.0.113.195",
    "203.0.113.195, 10.0.0.1",
    "1.1.1.1, 203.0.113.195, 10.0.0.1",
    "10.0.0.1, 10.0.0.2",
    "203.0.113.195:8080, 10.0.0.1:443",
    "[2001:db8::1], 10.0.0.1",
    "",
    "   ",
    ",,,,",
    "unknown, 127.0.0.1",
    "999.999.999.999",
};

static const char *const magnus_fuzz_fwd_seeds[] = {
    "for=198.51.100.17",
    "for=198.51.100.17;proto=http;by=10.0.0.1",
    "for=\"198.51.100.17:8080\", for=\"10.0.0.2\"",
    "for=\"[2001:db8::1]:443\", for=198.51.100.17",
    "by=10.0.0.1;for=198.51.100.17;proto=https;host=example.com",
    "for=_hidden, for=unknown",
    "",
    ";;;",
    "for=",
    "for=\"\"",
};

static const char *const magnus_fuzz_proxy_v1_seeds[] = {
    "PROXY TCP4 192.168.1.100 10.0.0.1 54321 80\r\n",
    "PROXY UNKNOWN\r\n",
    "PROXY TCP6 2001:db8::1 2001:db8::2 1234 443\r\n",
    "PROXY TCP4 1.2.3.4 5.6.7.8 0 0\r\n",
    "PROXY",
    "PROXY TCP4\r\n",
    "GET / HTTP/1.1\r\n",
    "\x16\x03\x01\x00\xa0",
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
            buffer[index] = (char) (",;:= \"\r\n\t"[magnus_fuzz_rand() % 9]);
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
    const char *seed_env = getenv("MAGNUS_FUZZ_SEED");
    unsigned long iterations;
    const char *iterations_env = getenv("MAGNUS_FUZZ_ITERATIONS");
    magnus_cidr_t trusted[2];
    (void) magnus_route_parse_cidr("10.0.0.0/8", &trusted[0].network, &trusted[0].prefix_length);
    (void) magnus_route_parse_cidr("172.16.0.0/12", &trusted[1].network, &trusted[1].prefix_length);

    magnus_fuzz_state = seed_env != NULL ? (uint32_t) strtoul(seed_env, NULL, 10)
                                         : 0x2545f491u;
    if (magnus_fuzz_state == 0) magnus_fuzz_state = 1;
    iterations = iterations_env != NULL
        ? strtoul(iterations_env, NULL, 10) : MAGNUS_FUZZ_ITERATIONS;

    /* Base v2 template */
    unsigned char v2_base[28] = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        0x21, 0x11, 0x00, 0x0C,
        192, 168, 50, 75,
        10, 0, 0, 1,
        0x1F, 0x90, 0x00, 0x50
    };

    for (unsigned long iteration = 0; iteration < iterations; iteration++) {
        /* Fuzz X-Forwarded-For & Forwarded */
        {
            magnus_http_request_t req;
            struct in_addr out_ip;
            memset(&req, 0, sizeof(req));

            char xff_buf[MAGNUS_FUZZ_MAX_FIELD];
            size_t xff_seed_idx = magnus_fuzz_rand() % (sizeof(magnus_fuzz_xff_seeds) / sizeof(magnus_fuzz_xff_seeds[0]));
            size_t xff_len = strlen(magnus_fuzz_xff_seeds[xff_seed_idx]);
            memcpy(xff_buf, magnus_fuzz_xff_seeds[xff_seed_idx], xff_len);
            unsigned xff_mut = 1 + (magnus_fuzz_rand() % 4);
            for (unsigned m = 0; m < xff_mut; m++)
                magnus_fuzz_mutate(xff_buf, &xff_len, sizeof(xff_buf));
            if (xff_len >= sizeof(req.headers[0].value)) xff_len = sizeof(req.headers[0].value) - 1;
            strcpy(req.headers[0].name, "X-Forwarded-For");
            memcpy(req.headers[0].value, xff_buf, xff_len);
            req.headers[0].value[xff_len] = '\0';
            req.header_count = 1;

            (void) magnus_realip_resolve_headers(&req, trusted, 2, &out_ip);

            /* Also test Forwarded */
            char fwd_buf[MAGNUS_FUZZ_MAX_FIELD];
            size_t fwd_seed_idx = magnus_fuzz_rand() % (sizeof(magnus_fuzz_fwd_seeds) / sizeof(magnus_fuzz_fwd_seeds[0]));
            size_t fwd_len = strlen(magnus_fuzz_fwd_seeds[fwd_seed_idx]);
            memcpy(fwd_buf, magnus_fuzz_fwd_seeds[fwd_seed_idx], fwd_len);
            unsigned fwd_mut = 1 + (magnus_fuzz_rand() % 4);
            for (unsigned m = 0; m < fwd_mut; m++)
                magnus_fuzz_mutate(fwd_buf, &fwd_len, sizeof(fwd_buf));
            if (fwd_len >= sizeof(req.headers[1].value)) fwd_len = sizeof(req.headers[1].value) - 1;
            strcpy(req.headers[1].name, "Forwarded");
            memcpy(req.headers[1].value, fwd_buf, fwd_len);
            req.headers[1].value[fwd_len] = '\0';
            req.header_count = 2;

            (void) magnus_realip_resolve_headers(&req, trusted, 2, &out_ip);
        }

        /* Fuzz PROXY v1 */
        {
            char v1_buf[256];
            size_t v1_seed_idx = magnus_fuzz_rand() % (sizeof(magnus_fuzz_proxy_v1_seeds) / sizeof(magnus_fuzz_proxy_v1_seeds[0]));
            size_t v1_len = strlen(magnus_fuzz_proxy_v1_seeds[v1_seed_idx]);
            memcpy(v1_buf, magnus_fuzz_proxy_v1_seeds[v1_seed_idx], v1_len);
            unsigned v1_mut = 1 + (magnus_fuzz_rand() % 4);
            for (unsigned m = 0; m < v1_mut; m++)
                magnus_fuzz_mutate(v1_buf, &v1_len, sizeof(v1_buf));

            size_t consumed = 0;
            struct in_addr src_ip = {0};
            (void) magnus_proxy_proto_parse(v1_buf, v1_len, &consumed, &src_ip);
        }

        /* Fuzz PROXY v2 */
        {
            char v2_buf[256];
            size_t v2_len = sizeof(v2_base);
            memcpy(v2_buf, v2_base, v2_len);
            unsigned v2_mut = 1 + (magnus_fuzz_rand() % 4);
            for (unsigned m = 0; m < v2_mut; m++)
                magnus_fuzz_mutate(v2_buf, &v2_len, sizeof(v2_buf));

            size_t consumed = 0;
            struct in_addr src_ip = {0};
            (void) magnus_proxy_proto_parse(v2_buf, v2_len, &consumed, &src_ip);
        }
    }

    printf("fuzz-realip: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
