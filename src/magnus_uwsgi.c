#include "magnus_uwsgi.h"

/* For MAGNUS_AFFINITY_COOKIE_NAME only -- reused rather than a second
 * hardcoded copy, same reasoning magnus_fastcgi.c's own identical
 * include already documents. */
#include "magnus_http.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void
magnus_uwsgi_write_header(unsigned char *out, unsigned char modifier1,
                          size_t vars_block_size, unsigned char modifier2)
{
    out[0] = modifier1;
    out[1] = (unsigned char) (vars_block_size & 0xff);        /* LE low */
    out[2] = (unsigned char) ((vars_block_size >> 8) & 0xff); /* LE high */
    out[3] = modifier2;
}

size_t
magnus_uwsgi_encode_var(const char *name, const char *value,
                        unsigned char *out, size_t out_capacity)
{
    size_t name_length = strlen(name);
    size_t value_length = strlen(value);
    size_t total = 2 + name_length + 2 + value_length;

    if (name_length > 0xffff || value_length > 0xffff) return 0;
    if (total > out_capacity) return 0;

    out[0] = (unsigned char) (name_length & 0xff);
    out[1] = (unsigned char) ((name_length >> 8) & 0xff);
    memcpy(out + 2, name, name_length);
    out[2 + name_length] = (unsigned char) (value_length & 0xff);
    out[2 + name_length + 1] = (unsigned char) ((value_length >> 8) & 0xff);
    memcpy(out + 2 + name_length + 2, value, value_length);
    return total;
}

int
magnus_uwsgi_translate_headers(const char *header_text,
                               size_t header_text_length,
                               size_t body_length, bool close_connection,
                               const char *affinity_cookie_value,
                               char *out, size_t out_capacity,
                               unsigned *out_status)
{
    char scratch[8192];
    char *saveptr = NULL;
    char *line;
    unsigned status = 200;
    char reason[64] = "OK";
    size_t total = 0;
    int written;
    bool first_line_is_status = false;
    bool skipped_first = false;

    if (header_text_length >= sizeof(scratch)) return -1;
    memcpy(scratch, header_text, header_text_length);
    scratch[header_text_length] = '\0';

    /* A real uWSGI server's first response line is a genuine HTTP
     * status line ("HTTP/<version> <status> [reason]"), never a CGI
     * "Status:" line -- see this file's own header comment for how
     * this was confirmed against a real server, not assumed. Only the
     * *first* line is ever checked (unlike magnus_fastcgi_translate_
     * headers()'s own scan-anywhere "Status:" search), since a real
     * HTTP status line is only ever meaningful in that position. */
    if (strncmp(scratch, "HTTP/", 5) == 0) {
        const char *p = scratch + 5;
        while (*p != '\0' && *p != ' ' && *p != '\r' && *p != '\n') p++;
        if (*p == ' ') {
            char *end;
            unsigned long parsed;
            p++;
            errno = 0;
            parsed = strtoul(p, &end, 10);
            if (errno == 0 && end != p && parsed >= 100 && parsed <= 599) {
                const char *reason_start;
                const char *reason_end;
                size_t reason_len;
                status = (unsigned) parsed;
                first_line_is_status = true;
                while (*end == ' ' || *end == '\t') end++;
                reason_start = end;
                reason_end = reason_start;
                while (*reason_end != '\0' && *reason_end != '\r'
                       && *reason_end != '\n')
                    reason_end++;
                reason_len = (size_t) (reason_end - reason_start);
                if (reason_len == 0) {
                    strcpy(reason, "OK");
                } else {
                    if (reason_len >= sizeof(reason))
                        reason_len = sizeof(reason) - 1;
                    memcpy(reason, reason_start, reason_len);
                    reason[reason_len] = '\0';
                }
            }
        }
    }

    written = snprintf(out, out_capacity, "HTTP/1.1 %u %s\r\n", status, reason);
    if (written < 0 || (size_t) written >= out_capacity) return -1;
    total = (size_t) written;

    for (line = strtok_r(scratch, "\r\n", &saveptr); line != NULL;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        char *colon;
        size_t name_length;
        char name[64];

        if (!skipped_first) {
            skipped_first = true;
            if (first_line_is_status) continue; /* already consumed above */
        }

        colon = strchr(line, ':');
        if (colon == NULL) continue;
        name_length = (size_t) (colon - line);
        if (name_length == 0 || name_length >= sizeof(name)) continue;
        memcpy(name, line, name_length);
        name[name_length] = '\0';
        if (strcasecmp(name, "content-length") == 0
            || strcasecmp(name, "connection") == 0
            || strcasecmp(name, "status") == 0)
            continue;
        written = snprintf(out + total, out_capacity - total, "%s\r\n", line);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    written = snprintf(out + total, out_capacity - total,
                       "Content-Length: %zu\r\nConnection: %s\r\n"
                       "X-Magnus-Via: magnus-uwsgi/0.1\r\n",
                       body_length, close_connection ? "close" : "keep-alive");
    if (written < 0 || (size_t) written >= out_capacity - total) return -1;
    total += (size_t) written;

    if (affinity_cookie_value != NULL) {
        written = snprintf(out + total, out_capacity - total,
                           "Set-Cookie: " MAGNUS_AFFINITY_COOKIE_NAME
                           "=%s; Path=/; HttpOnly; SameSite=Lax\r\n",
                           affinity_cookie_value);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    written = snprintf(out + total, out_capacity - total, "\r\n");
    if (written < 0 || (size_t) written >= out_capacity - total) return -1;
    total += (size_t) written;

    if (out_status != NULL) *out_status = status;
    return (int) total;
}
