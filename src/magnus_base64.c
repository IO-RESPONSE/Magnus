#include "magnus_base64.h"

static int
magnus_base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int
magnus_base64url_decode(const char *input, size_t input_length,
                        unsigned char *out, size_t out_capacity)
{
    size_t length = input_length;
    size_t out_length = 0;
    size_t full_quads;
    size_t tail;
    size_t index;

    /* Any number of trailing '=' is tolerated (not just the 0-2 a
     * well-formed encoding would ever actually need) -- stripping all of
     * them first and then validating what's left by its length keeps
     * this simple without accepting anything a strict decoder wouldn't:
     * an over-padded input like "A===" still correctly fails the length
     * check below once its (still-invalid) 1-character remainder is all
     * that's left. */
    while (length > 0 && input[length - 1] == '=') length--;
    if (length % 4 == 1) return -1;

    full_quads = length / 4;
    tail = length % 4;

    for (index = 0; index < full_quads; index++) {
        int a = magnus_base64_value(input[index * 4 + 0]);
        int b = magnus_base64_value(input[index * 4 + 1]);
        int c = magnus_base64_value(input[index * 4 + 2]);
        int d = magnus_base64_value(input[index * 4 + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        if (out_length + 3 > out_capacity) return -1;
        out[out_length++] = (unsigned char) ((a << 2) | (b >> 4));
        out[out_length++] = (unsigned char) ((b << 4) | (c >> 2));
        out[out_length++] = (unsigned char) ((c << 6) | d);
    }

    if (tail == 2) {
        int a = magnus_base64_value(input[full_quads * 4 + 0]);
        int b = magnus_base64_value(input[full_quads * 4 + 1]);
        if (a < 0 || b < 0) return -1;
        if (out_length + 1 > out_capacity) return -1;
        out[out_length++] = (unsigned char) ((a << 2) | (b >> 4));
    } else if (tail == 3) {
        int a = magnus_base64_value(input[full_quads * 4 + 0]);
        int b = magnus_base64_value(input[full_quads * 4 + 1]);
        int c = magnus_base64_value(input[full_quads * 4 + 2]);
        if (a < 0 || b < 0 || c < 0) return -1;
        if (out_length + 2 > out_capacity) return -1;
        out[out_length++] = (unsigned char) ((a << 2) | (b >> 4));
        out[out_length++] = (unsigned char) ((b << 4) | (c >> 2));
    }

    return (int) out_length;
}
