#include "magnus_route.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static bool
magnus_route_equal_ci(const char *value, size_t value_length, const char *expected)
{
    return value_length == strlen(expected)
        && strncasecmp(value, expected, value_length) == 0;
}

/* Finds `name=value` within a `;`-separated header value (a Cookie header's
 * value, or a `?`-delimited query string with `&`-separated pairs -- same
 * shape either way once the leading `?` and any fragment/param-separator
 * quirks are normalized by the caller) and copies `value` into `out`.
 * Returns false if `name` is absent or its value does not fit `out`. */
static bool
magnus_route_find_pair(const char *text, size_t text_length, char separator,
                       const char *name, char *out, size_t out_capacity)
{
    size_t name_length = strlen(name);
    const char *cursor = text;
    const char *end = text + text_length;

    while (cursor < end) {
        const char *pair_end = memchr(cursor, separator, (size_t) (end - cursor));
        const char *stop = pair_end != NULL ? pair_end : end;
        const char *scan = cursor;
        const char *eq;
        while (scan < stop && *scan == ' ') scan++;
        eq = memchr(scan, '=', (size_t) (stop - scan));
        if (eq != NULL && (size_t) (eq - scan) == name_length
            && strncmp(scan, name, name_length) == 0) {
            size_t value_length = (size_t) (stop - (eq + 1));
            if (value_length >= out_capacity) return false;
            memcpy(out, eq + 1, value_length);
            out[value_length] = '\0';
            return true;
        }
        cursor = pair_end != NULL ? pair_end + 1 : end;
    }
    return false;
}

bool
magnus_route_parse_cidr(const char *text, struct in_addr *network,
                        unsigned *prefix_length)
{
    char address[64];
    char *slash = strchr(text, '/');
    unsigned long prefix;
    char *end;
    size_t address_length;

    if (slash == NULL) return false;
    address_length = (size_t) (slash - text);
    if (address_length == 0 || address_length >= sizeof(address)) return false;
    memcpy(address, text, address_length);
    address[address_length] = '\0';
    if (inet_pton(AF_INET, address, network) != 1) return false;
    prefix = strtoul(slash + 1, &end, 10);
    if (end == slash + 1 || *end != '\0' || prefix > 32) return false;
    *prefix_length = (unsigned) prefix;
    return true;
}

bool
magnus_route_parse(const char *value, magnus_route_t *out, char *error,
                   size_t error_capacity)
{
    char buffer[512];
    char *saveptr = NULL;
    char *token;
    bool action_seen = false;

    memset(out, 0, sizeof(*out));
    if (strlen(value) >= sizeof(buffer)) {
        if (error != NULL && error_capacity > 0)
            snprintf(error, error_capacity, "route spec too long");
        return false;
    }
    strcpy(buffer, value);

    for (token = strtok_r(buffer, ";", &saveptr); token != NULL;
         token = strtok_r(NULL, ";", &saveptr)) {
        char *cursor = token;
        char *equals;
        char *colon;
        while (*cursor == ' ') cursor++;
        equals = strchr(cursor, '=');
        if (equals == NULL) {
            if (error != NULL && error_capacity > 0)
                snprintf(error, error_capacity,
                        "expected 'key=value' or 'key:name=value', got '%s'",
                        cursor);
            return false;
        }
        colon = memchr(cursor, ':', (size_t) (equals - cursor));

        if (colon == NULL && strncmp(cursor, "action", (size_t) (equals - cursor)) == 0
            && (size_t) (equals - cursor) == 6) {
            char *action_value = equals + 1;
            if (action_seen) {
                if (error != NULL && error_capacity > 0)
                    snprintf(error, error_capacity, "duplicate 'action'");
                return false;
            }
            if (strcmp(action_value, "proxy") == 0)
                out->action = MAGNUS_ROUTE_ACTION_PROXY;
            else if (strcmp(action_value, "deny") == 0)
                out->action = MAGNUS_ROUTE_ACTION_DENY;
            else if (strcmp(action_value, "static") == 0)
                out->action = MAGNUS_ROUTE_ACTION_STATIC;
            else if (strcmp(action_value, "grpc") == 0)
                out->action = MAGNUS_ROUTE_ACTION_GRPC;
            else {
                if (error != NULL && error_capacity > 0)
                    snprintf(error, error_capacity,
                            "'action' must be proxy, deny, static, or grpc, "
                            "got '%s'", action_value);
                return false;
            }
            action_seen = true;
            continue;
        }

        if (out->condition_count == MAGNUS_ROUTE_MAX_CONDITIONS) {
            if (error != NULL && error_capacity > 0)
                snprintf(error, error_capacity,
                        "too many conditions (max %d)",
                        MAGNUS_ROUTE_MAX_CONDITIONS);
            return false;
        }
        {
            magnus_route_condition_t *condition
                = &out->conditions[out->condition_count];
            char *key_end = colon != NULL ? colon : equals;
            size_t key_length = (size_t) (key_end - cursor);
            char *field_value = equals + 1;
            size_t value_length = strlen(field_value);

            if (colon != NULL) {
                char *name = colon + 1;
                size_t name_length = (size_t) (equals - name);
                magnus_route_match_kind_t kind;
                if (magnus_route_equal_ci(cursor, key_length, "header"))
                    kind = MAGNUS_ROUTE_MATCH_HEADER;
                else if (magnus_route_equal_ci(cursor, key_length, "cookie"))
                    kind = MAGNUS_ROUTE_MATCH_COOKIE;
                else if (magnus_route_equal_ci(cursor, key_length, "query"))
                    kind = MAGNUS_ROUTE_MATCH_QUERY;
                else {
                    if (error != NULL && error_capacity > 0)
                        snprintf(error, error_capacity,
                                "unrecognized condition '%.*s'",
                                (int) key_length, cursor);
                    return false;
                }
                if (name_length == 0 || name_length >= sizeof(condition->key)
                    || value_length >= sizeof(condition->value)) {
                    if (error != NULL && error_capacity > 0)
                        snprintf(error, error_capacity,
                                "'%.*s' name or value too long or empty",
                                (int) key_length, cursor);
                    return false;
                }
                condition->kind = kind;
                memcpy(condition->key, name, name_length);
                condition->key[name_length] = '\0';
                strcpy(condition->value, field_value);
            } else if (magnus_route_equal_ci(cursor, key_length, "host")) {
                if (value_length == 0 || value_length >= sizeof(condition->value)) {
                    if (error != NULL && error_capacity > 0)
                        snprintf(error, error_capacity, "'host' value too long or empty");
                    return false;
                }
                condition->kind = MAGNUS_ROUTE_MATCH_HOST;
                strcpy(condition->value, field_value);
            } else if (magnus_route_equal_ci(cursor, key_length, "path_prefix")) {
                if (value_length == 0 || field_value[0] != '/'
                    || value_length >= sizeof(condition->value)) {
                    if (error != NULL && error_capacity > 0)
                        snprintf(error, error_capacity,
                                "'path_prefix' must start with '/'");
                    return false;
                }
                condition->kind = MAGNUS_ROUTE_MATCH_PATH_PREFIX;
                strcpy(condition->value, field_value);
            } else if (magnus_route_equal_ci(cursor, key_length, "method")) {
                if (value_length == 0 || value_length >= sizeof(condition->value)) {
                    if (error != NULL && error_capacity > 0)
                        snprintf(error, error_capacity, "'method' value too long or empty");
                    return false;
                }
                condition->kind = MAGNUS_ROUTE_MATCH_METHOD;
                strcpy(condition->value, field_value);
            } else if (magnus_route_equal_ci(cursor, key_length, "source_cidr")) {
                if (!magnus_route_parse_cidr(field_value, &condition->cidr_network,
                                             &condition->cidr_prefix_length)) {
                    if (error != NULL && error_capacity > 0)
                        snprintf(error, error_capacity,
                                "'source_cidr' must be a.b.c.d/prefix, got '%s'",
                                field_value);
                    return false;
                }
                condition->kind = MAGNUS_ROUTE_MATCH_SOURCE_CIDR;
            } else {
                if (error != NULL && error_capacity > 0)
                    snprintf(error, error_capacity,
                            "unrecognized condition '%.*s'",
                            (int) key_length, cursor);
                return false;
            }
            out->condition_count++;
        }
    }

    if (!action_seen) {
        if (error != NULL && error_capacity > 0)
            snprintf(error, error_capacity, "route is missing 'action'");
        return false;
    }
    return true;
}

static bool
magnus_route_condition_matches(const magnus_route_condition_t *condition,
                               const magnus_http_request_t *request,
                               struct in_addr client_ip)
{
    switch (condition->kind) {
    case MAGNUS_ROUTE_MATCH_HOST:
        return strcasecmp(request->host, condition->value) == 0;
    case MAGNUS_ROUTE_MATCH_PATH_PREFIX: {
        size_t prefix_length = strlen(condition->value);
        return strncmp(request->target, condition->value, prefix_length) == 0;
    }
    case MAGNUS_ROUTE_MATCH_METHOD:
        return strcasecmp(request->method, condition->value) == 0;
    case MAGNUS_ROUTE_MATCH_HEADER: {
        const char *actual = magnus_http_header_find(request, condition->key);
        return actual != NULL && strcasecmp(actual, condition->value) == 0;
    }
    case MAGNUS_ROUTE_MATCH_COOKIE: {
        const char *cookie_header = magnus_http_header_find(request, "cookie");
        char actual[192];
        if (cookie_header == NULL) return false;
        if (!magnus_route_find_pair(cookie_header, strlen(cookie_header), ';',
                                    condition->key, actual, sizeof(actual)))
            return false;
        return strcmp(actual, condition->value) == 0;
    }
    case MAGNUS_ROUTE_MATCH_QUERY: {
        const char *question = strchr(request->target, '?');
        char actual[192];
        if (question == NULL) return false;
        question++;
        if (!magnus_route_find_pair(question, strlen(question), '&',
                                    condition->key, actual, sizeof(actual)))
            return false;
        return strcmp(actual, condition->value) == 0;
    }
    case MAGNUS_ROUTE_MATCH_SOURCE_CIDR: {
        uint32_t mask = condition->cidr_prefix_length == 0
            ? 0 : htonl(0xFFFFFFFFu << (32 - condition->cidr_prefix_length));
        return (client_ip.s_addr & mask)
            == (condition->cidr_network.s_addr & mask);
    }
    default:
        return false;
    }
}

bool
magnus_route_matches(const magnus_route_t *route,
                     const magnus_http_request_t *request,
                     struct in_addr client_ip)
{
    for (size_t i = 0; i < route->condition_count; i++)
        if (!magnus_route_condition_matches(&route->conditions[i], request,
                                            client_ip))
            return false;
    return true;
}
