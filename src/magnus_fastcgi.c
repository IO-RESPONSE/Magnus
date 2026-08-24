#include "magnus_fastcgi.h"

/* For MAGNUS_AFFINITY_COOKIE_NAME only (roadmap 5a-5) -- reused rather
 * than a second hardcoded copy of the cookie name, so a client that
 * bounces between action=proxy and action=fastcgi routes on the same
 * origin only ever sees one cookie name. */
#include "magnus_http.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void
magnus_fastcgi_write_header(unsigned char *out, unsigned char type,
                            uint16_t request_id, size_t content_length)
{
    out[0] = MAGNUS_FASTCGI_VERSION;
    out[1] = type;
    out[2] = (unsigned char) (request_id >> 8);
    out[3] = (unsigned char) (request_id & 0xff);
    out[4] = (unsigned char) (content_length >> 8);
    out[5] = (unsigned char) (content_length & 0xff);
    out[6] = 0; /* padding length -- always 0, see this file's own header
                 * comment on why */
    out[7] = 0; /* reserved */
}

void
magnus_fastcgi_write_begin_request_body(unsigned char *out, uint16_t role,
                                        unsigned char flags)
{
    out[0] = (unsigned char) (role >> 8);
    out[1] = (unsigned char) (role & 0xff);
    out[2] = flags;
    out[3] = 0;
    out[4] = 0;
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;
}

static size_t
magnus_fastcgi_encode_length(size_t length, unsigned char *out,
                             size_t out_capacity)
{
    if (length < 128) {
        if (out_capacity < 1) return 0;
        out[0] = (unsigned char) length;
        return 1;
    }
    /* 4-byte form: high bit of the first byte set, the remaining 31
     * bits (spread big-endian across all 4 bytes) carry the real
     * length -- length values this codebase ever actually sends never
     * come close to needing more than 31 bits, so no overflow check
     * beyond what the caller's own size_t already bounds. */
    if (out_capacity < 4) return 0;
    out[0] = (unsigned char) (((length >> 24) & 0x7f) | 0x80);
    out[1] = (unsigned char) ((length >> 16) & 0xff);
    out[2] = (unsigned char) ((length >> 8) & 0xff);
    out[3] = (unsigned char) (length & 0xff);
    return 4;
}

size_t
magnus_fastcgi_encode_nv(const char *name, const char *value,
                         unsigned char *out, size_t out_capacity)
{
    size_t name_length = 0;
    size_t value_length = 0;
    size_t offset = 0;
    size_t written;

    while (name[name_length] != '\0') name_length++;
    while (value[value_length] != '\0') value_length++;

    written = magnus_fastcgi_encode_length(name_length, out + offset,
                                           out_capacity - offset);
    if (written == 0) return 0;
    offset += written;

    written = magnus_fastcgi_encode_length(value_length, out + offset,
                                           out_capacity - offset);
    if (written == 0) return 0;
    offset += written;

    if (out_capacity - offset < name_length + value_length) return 0;
    for (size_t i = 0; i < name_length; i++) out[offset + i] = (unsigned char) name[i];
    offset += name_length;
    for (size_t i = 0; i < value_length; i++) out[offset + i] = (unsigned char) value[i];
    offset += value_length;

    return offset;
}

bool
magnus_fastcgi_read_header(const unsigned char *in, unsigned char *type,
                           uint16_t *request_id, size_t *content_length,
                           unsigned char *padding_length)
{
    if (in[0] != MAGNUS_FASTCGI_VERSION) return false;
    *type = in[1];
    *request_id = (uint16_t) ((in[2] << 8) | in[3]);
    *content_length = (size_t) ((in[4] << 8) | in[5]);
    *padding_length = in[6];
    return true;
}

/* memmem() is a GNU extension (magnus.c's own build already requests
 * _GNU_SOURCE, but this translation unit does not include magnus.c's
 * headers, so it is not guaranteed visible here) -- a tiny, direct
 * search is simpler than adding a feature-test-macro dependency just
 * for this one call. `needle_length` is always 2 or 4 in this file's
 * own two call sites below, never large enough for this naive scan to
 * matter. */
static const char *
magnus_fastcgi_memfind(const char *haystack, size_t haystack_length,
                       const char *needle, size_t needle_length)
{
    if (needle_length == 0 || haystack_length < needle_length) return NULL;
    for (size_t i = 0; i + needle_length <= haystack_length; i++) {
        if (memcmp(haystack + i, needle, needle_length) == 0)
            return haystack + i;
    }
    return NULL;
}

const char *
magnus_fastcgi_find_body(const char *data, size_t length,
                         size_t *header_text_length)
{
    const char *crlf = magnus_fastcgi_memfind(data, length, "\r\n\r\n", 4);
    const char *lf = magnus_fastcgi_memfind(data, length, "\n\n", 2);
    if (crlf != NULL && (lf == NULL || crlf <= lf)) {
        *header_text_length = (size_t) (crlf - data);
        return crlf + 4;
    }
    if (lf != NULL) {
        *header_text_length = (size_t) (lf - data);
        return lf + 2;
    }
    return NULL;
}

int
magnus_fastcgi_translate_headers(const char *header_text,
                                 size_t header_text_length,
                                 size_t body_length, bool close_connection,
                                 const char *affinity_cookie_value,
                                 const char *via,
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

    if (header_text_length >= sizeof(scratch)) return -1;
    memcpy(scratch, header_text, header_text_length);
    scratch[header_text_length] = '\0';

    /* First pass: just look for a Status: line, so the real status
     * line can be written first, in the conventional position, without
     * a second copy of the whole scratch buffer (strtok_r would
     * otherwise need one, since it mutates in place and this same
     * buffer is walked a second time below for the pass-through
     * headers). */
    {
        char probe[8192];
        char *probe_saveptr = NULL;
        char *probe_line;
        memcpy(probe, scratch, header_text_length + 1);
        for (probe_line = strtok_r(probe, "\r\n", &probe_saveptr);
             probe_line != NULL;
             probe_line = strtok_r(NULL, "\r\n", &probe_saveptr)) {
            if (strncasecmp(probe_line, "status:", 7) == 0) {
                char *value = probe_line + 7;
                char *end;
                unsigned long parsed;
                while (*value == ' ' || *value == '\t') value++;
                errno = 0;
                parsed = strtoul(value, &end, 10);
                if (errno != 0 || end == value || parsed < 100
                    || parsed > 599)
                    return -1;
                status = (unsigned) parsed;
                while (*end == ' ' || *end == '\t') end++;
                if (*end != '\0') {
                    strncpy(reason, end, sizeof(reason) - 1);
                    reason[sizeof(reason) - 1] = '\0';
                } else {
                    strcpy(reason, "OK");
                }
                break;
            }
        }
    }

    written = snprintf(out, out_capacity, "HTTP/1.1 %u %s\r\n", status, reason);
    if (written < 0 || (size_t) written >= out_capacity) return -1;
    total = (size_t) written;

    for (line = strtok_r(scratch, "\r\n", &saveptr); line != NULL;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        char *colon = strchr(line, ':');
        size_t name_length;
        char name[64];
        if (colon == NULL) continue;
        name_length = (size_t) (colon - line);
        if (name_length == 0 || name_length >= sizeof(name)) continue;
        memcpy(name, line, name_length);
        name[name_length] = '\0';
        if (strcasecmp(name, "status") == 0
            || strcasecmp(name, "content-length") == 0
            || strcasecmp(name, "connection") == 0)
            continue;
        written = snprintf(out + total, out_capacity - total, "%s\r\n", line);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    written = snprintf(out + total, out_capacity - total,
                       "Content-Length: %zu\r\nConnection: %s\r\n"
                       "X-Magnus-Via: %s\r\n",
                       body_length, close_connection ? "close" : "keep-alive",
                       via);
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
