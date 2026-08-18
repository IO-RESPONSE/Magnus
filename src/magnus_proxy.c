#include "magnus_proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *const magnus_proxy_hop_by_hop_headers[] = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade", NULL
};

bool
magnus_proxy_is_hop_by_hop(const char *name)
{
    size_t index;
    for (index = 0; magnus_proxy_hop_by_hop_headers[index] != NULL; index++) {
        if (strcasecmp(name, magnus_proxy_hop_by_hop_headers[index]) == 0) {
            return true;
        }
    }
    return false;
}

static bool
magnus_proxy_parse_status_line(char *line, unsigned *status, char *reason,
                               size_t reason_capacity)
{
    char *space = strchr(line, ' ');
    char *end;
    unsigned long code;

    if (space == NULL) return false;
    space++;
    code = strtoul(space, &end, 10);
    if (end == space || code < 100 || code > 599) return false;
    while (*end == ' ') end++;
    if (reason_capacity > 0) {
        strncpy(reason, end, reason_capacity - 1);
        reason[reason_capacity - 1] = '\0';
    }
    *status = (unsigned) code;
    return true;
}

int
magnus_proxy_sanitize_response_headers(char *raw, size_t header_length,
                                       char *out, size_t out_capacity,
                                       unsigned *out_status)
{
    char *saveptr = NULL;
    char *line;
    char reason[64] = "Upstream Response";
    unsigned status;
    int written;
    size_t total;

    (void) header_length;
    line = strtok_r(raw, "\r\n", &saveptr);
    if (line == NULL || !magnus_proxy_parse_status_line(line, &status, reason,
                                                         sizeof(reason))) {
        return -1;
    }

    written = snprintf(out, out_capacity, "HTTP/1.1 %u %s\r\n", status, reason);
    if (written < 0 || (size_t) written >= out_capacity) return -1;
    total = (size_t) written;

    for (line = strtok_r(NULL, "\r\n", &saveptr); line != NULL;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        char *colon = strchr(line, ':');
        char name[64];
        size_t name_length;

        if (colon == NULL) continue;
        name_length = (size_t) (colon - line);
        if (name_length == 0 || name_length >= sizeof(name)) continue;
        memcpy(name, line, name_length);
        name[name_length] = '\0';
        if (magnus_proxy_is_hop_by_hop(name)) continue;

        written = snprintf(out + total, out_capacity - total, "%s\r\n", line);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    written = snprintf(out + total, out_capacity - total,
                       "Connection: close\r\nX-Magnus-Via: magnus-proxy/0.1\r\n\r\n");
    if (written < 0 || (size_t) written >= out_capacity - total) return -1;
    total += (size_t) written;

    *out_status = status;
    return (int) total;
}
