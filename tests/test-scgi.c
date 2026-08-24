#include "magnus_scgi.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    /* Name-value encoding: NUL-terminated name, then NUL-terminated
     * value, concatenated -- no length prefix, unlike FastCGI's own
     * PARAMS shape. */
    {
        char buf[64];
        size_t n = magnus_scgi_encode_nv("REQUEST_METHOD", "GET", buf,
                                         sizeof(buf));
        assert(n == 14 + 1 + 3 + 1);
        assert(memcmp(buf, "REQUEST_METHOD", 14) == 0);
        assert(buf[14] == '\0');
        assert(memcmp(buf + 15, "GET", 3) == 0);
        assert(buf[18] == '\0');
    }

    /* Too small a buffer is rejected, not silently truncated. */
    {
        char buf[4];
        assert(magnus_scgi_encode_nv("REQUEST_METHOD", "GET", buf,
                                     sizeof(buf)) == 0);
    }

    /* Empty value is still two NUL terminators total: name\0\0. */
    {
        char buf[16];
        size_t n = magnus_scgi_encode_nv("SCGI", "", buf, sizeof(buf));
        assert(n == 4 + 1 + 0 + 1);
        assert(memcmp(buf, "SCGI", 4) == 0);
        assert(buf[4] == '\0');
        assert(buf[5] == '\0');
    }

    /* Netstring length prefix. */
    {
        char buf[16];
        size_t n = magnus_scgi_write_netstring_prefix(70, buf, sizeof(buf));
        assert(n == 3);
        assert(memcmp(buf, "70:", 3) == 0);
    }

    /* Zero-length payload still gets a real prefix ("0:"), not treated
     * as an error -- an empty header block is a degenerate but valid
     * netstring. */
    {
        char buf[16];
        size_t n = magnus_scgi_write_netstring_prefix(0, buf, sizeof(buf));
        assert(n == 2);
        assert(memcmp(buf, "0:", 2) == 0);
    }

    /* Too small a buffer is rejected. */
    {
        char buf[2];
        assert(magnus_scgi_write_netstring_prefix(12345, buf, sizeof(buf))
              == 0);
    }

    /* End-to-end assembly against the SCGI protocol specification's own
     * published canonical example (https://python.ca/scgi/protocol.txt):
     * a header block of CONTENT_LENGTH/SCGI/REQUEST_METHOD/REQUEST_URI
     * pairs whose netstring-encoded length the spec itself states is
     * exactly 70 bytes -- reproduced here byte-for-byte as this
     * codebase's own build_request() (magnus.c) would assemble it,
     * confirming this module's two low-level primitives compose into
     * spec-conformant output, not just that each one is individually
     * correct in isolation. */
    {
        char headers[128];
        size_t headers_length = 0;
        char prefix[16];
        size_t prefix_length;
        char out[160];
        size_t offset = 0;
        static const char expected[] =
            "70:CONTENT_LENGTH\x00" "27\x00" "SCGI\x00" "1\x00"
            "REQUEST_METHOD\x00" "POST\x00" "REQUEST_URI\x00"
            "/deepthought\x00" ",";
        /* Each \x00 above is deliberately the last character of its own
         * adjacent string literal -- concatenation happens after escape
         * sequences are resolved within each literal, so this avoids
         * \x00 swallowing the hex-digit-looking characters that follow
         * it in the actual data (e.g. "27", "1") the way a single
         * unsplit literal would. */
        size_t expected_length = sizeof(expected) - 1; /* drop the NUL
                                                          * the compiler
                                                          * appends at
                                                          * the very end */

        headers_length += magnus_scgi_encode_nv("CONTENT_LENGTH", "27",
            headers + headers_length, sizeof(headers) - headers_length);
        headers_length += magnus_scgi_encode_nv("SCGI", "1",
            headers + headers_length, sizeof(headers) - headers_length);
        headers_length += magnus_scgi_encode_nv("REQUEST_METHOD", "POST",
            headers + headers_length, sizeof(headers) - headers_length);
        headers_length += magnus_scgi_encode_nv("REQUEST_URI",
            "/deepthought", headers + headers_length,
            sizeof(headers) - headers_length);
        assert(headers_length == 70);

        prefix_length = magnus_scgi_write_netstring_prefix(headers_length,
            prefix, sizeof(prefix));
        assert(prefix_length > 0);

        memcpy(out + offset, prefix, prefix_length);
        offset += prefix_length;
        memcpy(out + offset, headers, headers_length);
        offset += headers_length;
        out[offset++] = ',';

        assert(offset == expected_length);
        assert(memcmp(out, expected, expected_length) == 0);
    }

    printf("test-scgi: all assertions passed\n");
    return 0;
}
