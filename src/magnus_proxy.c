#include "magnus_proxy.h"
#include "magnus_http.h"

#include <ctype.h>
#include <errno.h>
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
                                       const char *affinity_cookie_value,
                                       bool client_wants_close,
                                       magnus_proxy_response_info_t *info)
{
    char *saveptr = NULL;
    char *line;
    char reason[64] = "Upstream Response";
    unsigned status;
    int written;
    size_t total;
    bool content_length_seen = false;
    bool content_length_valid = true;
    bool transfer_encoding_seen = false;
    bool upstream_wants_close = false;
    unsigned long content_length = 0;

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
        char *value;

        if (colon == NULL) continue;
        name_length = (size_t) (colon - line);
        if (name_length == 0 || name_length >= sizeof(name)) continue;
        memcpy(name, line, name_length);
        name[name_length] = '\0';

        value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;

        /* Inspect Connection/Content-Length/Transfer-Encoding for framing
         * purposes even though (being hop-by-hop) none of them get
         * forwarded verbatim below -- what the client and the connection
         * pool actually see is decided from these facts, not by passing
         * the upstream's own header through. */
        if (strcasecmp(name, "connection") == 0) {
            if (strcasestr(value, "close") != NULL) upstream_wants_close = true;
        } else if (strcasecmp(name, "transfer-encoding") == 0) {
            transfer_encoding_seen = true;
        } else if (strcasecmp(name, "content-length") == 0) {
            char *end;
            unsigned long parsed;
            if (content_length_seen) {
                content_length_valid = false;
            } else {
                content_length_seen = true;
                for (const char *scan = value; *scan != '\0'; scan++)
                    if (!isdigit((unsigned char) *scan))
                        content_length_valid = false;
                if (content_length_valid) {
                    errno = 0;
                    parsed = strtoul(value, &end, 10);
                    if (errno != 0 || end == value || *end != '\0')
                        content_length_valid = false;
                    else
                        content_length = parsed;
                }
            }
        }

        if (magnus_proxy_is_hop_by_hop(name)) continue;

        written = snprintf(out + total, out_capacity - total, "%s\r\n", line);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    if (content_length_seen && !content_length_valid) return -1;

    if (affinity_cookie_value != NULL) {
        written = snprintf(out + total, out_capacity - total,
                           "Set-Cookie: " MAGNUS_AFFINITY_COOKIE_NAME
                           "=%s; Path=/; HttpOnly; SameSite=Lax\r\n",
                           affinity_cookie_value);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    info->status = status;
    info->has_content_length = content_length_seen && !transfer_encoding_seen;
    info->content_length = info->has_content_length ? content_length : 0;
    info->upstream_poolable = info->has_content_length && !upstream_wants_close;
    info->keep_client_alive = !client_wants_close && info->has_content_length;

    written = snprintf(out + total, out_capacity - total,
                       "Connection: %s\r\nX-Magnus-Via: magnus-proxy/0.1\r\n\r\n",
                       info->keep_client_alive ? "keep-alive" : "close");
    if (written < 0 || (size_t) written >= out_capacity - total) return -1;
    total += (size_t) written;

    return (int) total;
}
