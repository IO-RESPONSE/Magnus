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
        if (magnus_equal_ci(cursor, name_length, "host")) {
            if (host_seen || value == line_end) return MAGNUS_HTTP_BAD_REQUEST;
            host_seen = true;
        }
        if (magnus_equal_ci(cursor, name_length, "connection")) {
            size_t value_length = (size_t) (line_end - value);
            if (magnus_equal_ci(value, value_length, "close"))
                request->close_connection = true;
            else if (!request->http_11
                     && magnus_equal_ci(value, value_length, "keep-alive"))
                request->close_connection = false;
        }
        cursor = line_end + 2;
    }
    if (request->http_11 && !host_seen) return MAGNUS_HTTP_BAD_REQUEST;
    request->head_only = strcmp(request->method, "HEAD") == 0;
    return MAGNUS_HTTP_OK;
}
