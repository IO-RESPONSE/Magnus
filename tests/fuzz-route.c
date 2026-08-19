/* Mutation-based fuzz driver for magnus_route_matches() / the
 * magnus_route_find_pair() cookie/query parsing it relies on -- the part
 * of the route matcher that processes attacker-influenced data (Host,
 * Cookie, and query-string bytes out of an already-parsed request), as
 * opposed to magnus_route_parse(), which only ever sees admin-controlled
 * config file content. Same approach as tests/fuzz-http.c: seeded,
 * deterministic, crash/ASan-UBSan-finding is the only failure mode this
 * program cares about -- a route simply not matching mutated garbage is
 * a correct, expected outcome. */

#include "magnus_route.h"
#include "magnus_http.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGNUS_FUZZ_ITERATIONS 200000
#define MAGNUS_FUZZ_MAX_FIELD 256

static const char *const magnus_fuzz_hosts[] = {
    "api.example.com", "", "a", "API.EXAMPLE.COM",
    "host-with-a-very-long-name-that-is-close-to-the-two-hundred-fifty-"
    "five-byte-field-limit-and-then-some-more-padding-characters-here.example.com",
};

static const char *const magnus_fuzz_cookie_headers[] = {
    "session=abc; other=x",
    "session=; other=x",
    "session=abc",
    "",
    ";;;",
    "a=b;a=c;a=d",
    "session=abc;;session=xyz",
    " session = abc ; other=y",
};

static const char *const magnus_fuzz_targets[] = {
    "/v1/widgets?debug=1",
    "/",
    "/?",
    "/?a=1&b=2&a=3",
    "/path?",
    "/path?=&=&=",
    "/path?debug",
    "/path?debug=",
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
            buffer[index] = (char) ("=&; \t"[magnus_fuzz_rand() % 5]);
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

static void
magnus_fuzz_field(char *field, size_t field_capacity, const char *const *seeds,
                  size_t seed_count)
{
    char buffer[MAGNUS_FUZZ_MAX_FIELD];
    size_t length;
    unsigned mutations;
    size_t seed_index = magnus_fuzz_rand() % seed_count;

    length = strlen(seeds[seed_index]);
    if (length >= sizeof(buffer)) length = sizeof(buffer) - 1;
    memcpy(buffer, seeds[seed_index], length);
    mutations = 1 + (magnus_fuzz_rand() % 6);
    for (unsigned m = 0; m < mutations; m++)
        magnus_fuzz_mutate(buffer, &length, sizeof(buffer));
    if (length >= field_capacity) length = field_capacity - 1;
    memcpy(field, buffer, length);
    field[length] = '\0';
}

int
main(void)
{
    const char *seed_env = getenv("MAGNUS_FUZZ_SEED");
    unsigned long iterations;
    const char *iterations_env = getenv("MAGNUS_FUZZ_ITERATIONS");
    magnus_route_t routes[7];
    struct in_addr client_ip = {0};

    magnus_fuzz_state = seed_env != NULL ? (uint32_t) strtoul(seed_env, NULL, 10)
                                         : 0x2545f491u;
    if (magnus_fuzz_state == 0) magnus_fuzz_state = 1;
    iterations = iterations_env != NULL
        ? strtoul(iterations_env, NULL, 10) : MAGNUS_FUZZ_ITERATIONS;

    /* One route per condition kind, fixed and valid -- only the *request*
     * fields being matched against are mutated. */
    (void) magnus_route_parse("host=api.example.com; action=proxy", &routes[0],
                              NULL, 0);
    (void) magnus_route_parse("path_prefix=/v1; action=proxy", &routes[1],
                              NULL, 0);
    (void) magnus_route_parse("method=POST; action=proxy", &routes[2], NULL, 0);
    (void) magnus_route_parse("header:X-Debug=1; action=deny", &routes[3],
                              NULL, 0);
    (void) magnus_route_parse("cookie:session=abc; action=static", &routes[4],
                              NULL, 0);
    (void) magnus_route_parse("query:debug=1; action=proxy", &routes[5],
                              NULL, 0);
    (void) magnus_route_parse("source_cidr=10.0.0.0/8; action=deny",
                              &routes[6], NULL, 0);

    for (unsigned long iteration = 0; iteration < iterations; iteration++) {
        magnus_http_request_t request;
        memset(&request, 0, sizeof(request));
        strcpy(request.method, "POST");
        magnus_fuzz_field(request.target, sizeof(request.target),
                          magnus_fuzz_targets,
                          sizeof(magnus_fuzz_targets) / sizeof(magnus_fuzz_targets[0]));
        magnus_fuzz_field(request.host, sizeof(request.host), magnus_fuzz_hosts,
                          sizeof(magnus_fuzz_hosts) / sizeof(magnus_fuzz_hosts[0]));
        {
            char cookie_value[MAGNUS_FUZZ_MAX_FIELD];
            magnus_fuzz_field(cookie_value, sizeof(cookie_value),
                              magnus_fuzz_cookie_headers,
                              sizeof(magnus_fuzz_cookie_headers)
                                  / sizeof(magnus_fuzz_cookie_headers[0]));
            size_t copy_length = strlen(cookie_value);
            if (copy_length >= sizeof(request.headers[0].value))
                copy_length = sizeof(request.headers[0].value) - 1;
            strcpy(request.headers[0].name, "Cookie");
            memcpy(request.headers[0].value, cookie_value, copy_length);
            request.headers[0].value[copy_length] = '\0';
            strcpy(request.headers[1].name, "X-Debug");
            strcpy(request.headers[1].value,
                  (magnus_fuzz_rand() % 2) == 0 ? "1" : "0");
            request.header_count = 2;
        }

        for (size_t r = 0; r < sizeof(routes) / sizeof(routes[0]); r++)
            (void) magnus_route_matches(&routes[r], &request, client_ip);
    }

    printf("fuzz-route: %lu iterations, no crash (seed=%u)\n", iterations,
           magnus_fuzz_state);
    return 0;
}
