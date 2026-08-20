#include "magnus_http.h"

#include <ctype.h>
#include <string.h>
#include <strings.h>

static bool
magnus_token_character(unsigned char value)
{
    return isalnum(value) || strchr("!#$%&'*+-.^_`|~", value) != NULL;
}

static bool
magnus_equal_ci(const char *left, size_t left_length, const char *right)
{
    return left_length == strlen(right)
        && strncasecmp(left, right, left_length) == 0;
}

bool
magnus_http_extract_cookie(const char *value, size_t value_length,
                           const char *name, char *out, size_t out_capacity)
{
    size_t name_length = strlen(name);
    const char *cursor = value;
    const char *end = value + value_length;

    while (cursor < end) {
        const char *pair_end = memchr(cursor, ';', (size_t) (end - cursor));
        const char *stop = pair_end != NULL ? pair_end : end;
        const char *scan = cursor;
        const char *eq;
        while (scan < stop && *scan == ' ') scan++;
        eq = memchr(scan, '=', (size_t) (stop - scan));
        if (eq != NULL && (size_t) (eq - scan) == name_length
            && strncasecmp(scan, name, name_length) == 0) {
            size_t token_length = (size_t) (stop - (eq + 1));
            if (token_length >= out_capacity) return false;
            memcpy(out, eq + 1, token_length);
            out[token_length] = '\0';
            return true;
        }
        cursor = pair_end != NULL ? pair_end + 1 : end;
    }
    return false;
}

magnus_http_result_t
magnus_http_parse(const char *data, size_t length, magnus_http_request_t *request)
{
    const char *cursor = data;
    const char *end = data + length;
    const char *space;
    const char *line_end;
    size_t field_length;
    bool host_seen = false;

    memset(request, 0, sizeof(*request));
    line_end = memmem(cursor, (size_t) (end - cursor), "\r\n", 2);
    if (line_end == NULL) return MAGNUS_HTTP_BAD_REQUEST;
    space = memchr(cursor, ' ', (size_t) (line_end - cursor));
    if (space == NULL || space == cursor) return MAGNUS_HTTP_BAD_REQUEST;
    field_length = (size_t) (space - cursor);
    if (field_length >= sizeof(request->method)) return MAGNUS_HTTP_BAD_REQUEST;
    for (size_t i = 0; i < field_length; i++)
        if (!magnus_token_character((unsigned char) cursor[i]))
            return MAGNUS_HTTP_BAD_REQUEST;
    memcpy(request->method, cursor, field_length);

    cursor = space + 1;
    space = memchr(cursor, ' ', (size_t) (line_end - cursor));
    if (space == NULL || space == cursor || cursor[0] != '/')
        return MAGNUS_HTTP_BAD_REQUEST;
    field_length = (size_t) (space - cursor);
    if (field_length >= sizeof(request->target)) return MAGNUS_HTTP_URI_TOO_LONG;
    for (size_t i = 0; i < field_length; i++)
        if ((unsigned char) cursor[i] < 0x20 || cursor[i] == 0x7f)
            return MAGNUS_HTTP_BAD_REQUEST;
    memcpy(request->target, cursor, field_length);

    cursor = space + 1;
    field_length = (size_t) (line_end - cursor);
    if (field_length == 8 && memcmp(cursor, "HTTP/1.1", 8) == 0)
        request->http_11 = true;
    else if (!(field_length == 8 && memcmp(cursor, "HTTP/1.0", 8) == 0))
        return MAGNUS_HTTP_VERSION_UNSUPPORTED;
    request->close_connection = !request->http_11;

    cursor = line_end + 2;
    while (cursor < end && !(cursor[0] == '\r' && cursor + 1 < end
                             && cursor[1] == '\n')) {
        const char *colon;
        const char *value;
        size_t name_length;
        line_end = memmem(cursor, (size_t) (end - cursor), "\r\n", 2);
        if (line_end == NULL || line_end == cursor) return MAGNUS_HTTP_BAD_REQUEST;
        colon = memchr(cursor, ':', (size_t) (line_end - cursor));
        if (colon == NULL || colon == cursor) return MAGNUS_HTTP_BAD_REQUEST;
        name_length = (size_t) (colon - cursor);
        for (size_t i = 0; i < name_length; i++)
            if (!magnus_token_character((unsigned char) cursor[i]))
                return MAGNUS_HTTP_BAD_REQUEST;
        value = colon + 1;
        while (value < line_end && (*value == ' ' || *value == '\t')) value++;
        for (const char *scan = value; scan < line_end; scan++)
            if (((unsigned char) *scan < 0x20 && *scan != '\t') || *scan == 0x7f)
                return MAGNUS_HTTP_BAD_REQUEST;
        if (request->header_count < MAGNUS_HTTP_MAX_HEADERS) {
            magnus_http_header_t *stored
                = &request->headers[request->header_count];
            size_t value_length = (size_t) (line_end - value);
            size_t stored_name_length = name_length < sizeof(stored->name) - 1
                ? name_length : sizeof(stored->name) - 1;
            size_t stored_value_length
                = value_length < sizeof(stored->value) - 1
                ? value_length : sizeof(stored->value) - 1;
            memcpy(stored->name, cursor, stored_name_length);
            stored->name[stored_name_length] = '\0';
            memcpy(stored->value, value, stored_value_length);
            stored->value[stored_value_length] = '\0';
            request->header_count++;
        }
        if (magnus_equal_ci(cursor, name_length, "host")) {
            size_t value_length = (size_t) (line_end - value);
            if (host_seen || value == line_end) return MAGNUS_HTTP_BAD_REQUEST;
            host_seen = true;
            if (value_length < sizeof(request->host)) {
                memcpy(request->host, value, value_length);
                request->host[value_length] = '\0';
            }
        }
        if (magnus_equal_ci(cursor, name_length, "connection")) {
            size_t value_length = (size_t) (line_end - value);
            if (magnus_equal_ci(value, value_length, "close"))
                request->close_connection = true;
            else if (!request->http_11
                     && magnus_equal_ci(value, value_length, "keep-alive"))
                request->close_connection = false;
        }
        if (magnus_equal_ci(cursor, name_length, "cookie")) {
            size_t value_length = (size_t) (line_end - value);
            (void) magnus_http_extract_cookie(value, value_length,
                                         MAGNUS_AFFINITY_COOKIE_NAME,
                                         request->affinity_key,
                                         sizeof(request->affinity_key));
        }
        if (magnus_equal_ci(cursor, name_length, "content-length")) {
            size_t value_length = (size_t) (line_end - value);
            unsigned long parsed_length = 0;
            /* A second Content-Length (even if identical) and a value that
             * does not fit our digit budget are both rejected outright --
             * duplicate/ambiguous length headers are a request-smuggling
             * vector, not something to resolve by picking one. */
            if (request->has_content_length || value_length == 0
                || value_length > 18)
                return MAGNUS_HTTP_BAD_REQUEST;
            for (size_t i = 0; i < value_length; i++) {
                if (!isdigit((unsigned char) value[i]))
                    return MAGNUS_HTTP_BAD_REQUEST;
                parsed_length = parsed_length * 10
                    + (unsigned long) (value[i] - '0');
            }
            request->content_length = parsed_length;
            request->has_content_length = true;
        }
        if (magnus_equal_ci(cursor, name_length, "transfer-encoding")) {
            /* Chunked request bodies are not implemented yet. Rejecting
             * any Transfer-Encoding outright (rather than only unknown
             * codings) also means a request can never carry both it and
             * Content-Length past this point -- one fewer smuggling
             * ambiguity to reason about. */
            return MAGNUS_HTTP_BAD_REQUEST;
        }
        cursor = line_end + 2;
    }
    if (request->http_11 && !host_seen) return MAGNUS_HTTP_BAD_REQUEST;
    request->head_only = strcmp(request->method, "HEAD") == 0;
    return MAGNUS_HTTP_OK;
}

const char *
magnus_http_header_find(const magnus_http_request_t *request, const char *name)
{
    for (size_t i = 0; i < request->header_count; i++)
        if (strcasecmp(request->headers[i].name, name) == 0)
            return request->headers[i].value;
    return NULL;
}
