#include "magnus_scgi.h"

#include <stdio.h>
#include <string.h>

size_t
magnus_scgi_encode_nv(const char *name, const char *value, char *out,
                      size_t out_capacity)
{
    size_t name_length = strlen(name);
    size_t value_length = strlen(value);
    size_t total = name_length + 1 + value_length + 1;

    if (total > out_capacity) return 0;
    memcpy(out, name, name_length);
    out[name_length] = '\0';
    memcpy(out + name_length + 1, value, value_length);
    out[name_length + 1 + value_length] = '\0';
    return total;
}

size_t
magnus_scgi_write_netstring_prefix(size_t payload_length, char *out,
                                   size_t out_capacity)
{
    int written = snprintf(out, out_capacity, "%zu:", payload_length);
    if (written < 0 || (size_t) written >= out_capacity) return 0;
    return (size_t) written;
}
