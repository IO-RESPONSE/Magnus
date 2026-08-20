#include "magnus_base64.h"

#include <assert.h>
#include <string.h>

int
main(void)
{
    unsigned char out[64];
    int result;

    /* RFC 4648 test vectors (base64url is identical to base64 for
     * alphanumeric-only output; the '-'/'_' substitution only matters
     * once the encoding would otherwise need '+'/'/'). */
    result = magnus_base64url_decode("", 0, out, sizeof(out));
    assert(result == 0);

    result = magnus_base64url_decode("Zg", 2, out, sizeof(out));
    assert(result == 1 && memcmp(out, "f", 1) == 0);

    result = magnus_base64url_decode("Zm8", 3, out, sizeof(out));
    assert(result == 2 && memcmp(out, "fo", 2) == 0);

    result = magnus_base64url_decode("Zm9v", 4, out, sizeof(out));
    assert(result == 3 && memcmp(out, "foo", 3) == 0);

    result = magnus_base64url_decode("Zm9vYg", 6, out, sizeof(out));
    assert(result == 4 && memcmp(out, "foob", 4) == 0);

    result = magnus_base64url_decode("Zm9vYmE", 7, out, sizeof(out));
    assert(result == 5 && memcmp(out, "fooba", 5) == 0);

    result = magnus_base64url_decode("Zm9vYmFy", 8, out, sizeof(out));
    assert(result == 6 && memcmp(out, "foobar", 6) == 0);

    /* Padding tolerated, not required. */
    result = magnus_base64url_decode("Zg==", 4, out, sizeof(out));
    assert(result == 1 && memcmp(out, "f", 1) == 0);
    result = magnus_base64url_decode("Zm8=", 4, out, sizeof(out));
    assert(result == 2 && memcmp(out, "fo", 2) == 0);

    /* '-'/'_' alphabet, not '+'/'/': bytes 0xfb 0xff 0xbf encode (in
     * standard base64) as "+/+/" -- base64url must use "-_-_" for the
     * same bytes instead. */
    {
        unsigned char raw[3] = {0xfb, 0xff, 0xbf};
        result = magnus_base64url_decode("-_-_", 4, out, sizeof(out));
        assert(result == 3 && memcmp(out, raw, 3) == 0);
    }

    /* A real HTTP2-Settings-shaped payload: two 6-byte settings entries
     * (id=uint16 big-endian, value=uint32 big-endian). */
    {
        unsigned char settings[12] = {
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
            0x00, 0x04, 0x00, 0x00, 0xff, 0xff,
        };
        char encoded[32];
        /* base64url of the 12-byte settings block above. */
        strcpy(encoded, "AAMAAABkAAQAAP__");
        result = magnus_base64url_decode(encoded, strlen(encoded), out,
                                         sizeof(out));
        assert(result == 12 && memcmp(out, settings, 12) == 0);
    }

    /* Invalid: a length of 4n+1 can never decode (a single leftover
     * base64 character does not encode a whole byte). */
    result = magnus_base64url_decode("A", 1, out, sizeof(out));
    assert(result == -1);
    result = magnus_base64url_decode("AAAAA", 5, out, sizeof(out));
    assert(result == -1);

    /* Invalid: a character outside the base64url alphabet (including
     * '+'/'/' themselves, which are *not* valid in base64url). */
    result = magnus_base64url_decode("+g==", 4, out, sizeof(out));
    assert(result == -1);
    result = magnus_base64url_decode("/g==", 4, out, sizeof(out));
    assert(result == -1);
    result = magnus_base64url_decode("Z!==", 4, out, sizeof(out));
    assert(result == -1);

    /* Invalid: over-padded down to an unrecoverable 1-character tail. */
    result = magnus_base64url_decode("A===", 4, out, sizeof(out));
    assert(result == -1);

    /* Output-capacity overflow must be rejected, never partially
     * written past the caller's buffer. */
    {
        unsigned char tiny[2];
        result = magnus_base64url_decode("Zm9v", 4, tiny, sizeof(tiny));
        assert(result == -1);
    }

    return 0;
}
