#include "magnus_h2.h"

#include <assert.h>
#include <string.h>

int
main(void)
{
    const unsigned char *out;
    unsigned char outlen;

    /* Client offers exactly h2: matched. */
    {
        const unsigned char list[] = {2, 'h', '2'};
        assert(magnus_h2_alpn_select_callback(NULL, &out, &outlen, list,
                                              sizeof(list), NULL)
               == SSL_TLSEXT_ERR_OK);
        assert(outlen == 2);
        assert(memcmp(out, "h2", 2) == 0);
    }

    /* Client offers http/1.1 then h2: still matched (order in the
     * client's list does not matter -- magnus only ever has one
     * candidate, so there is no server-side preference to apply). */
    {
        const unsigned char list[] = {8, 'h','t','t','p','/','1','.','1', 2,'h','2'};
        assert(magnus_h2_alpn_select_callback(NULL, &out, &outlen, list,
                                              sizeof(list), NULL)
               == SSL_TLSEXT_ERR_OK);
        assert(outlen == 2);
        assert(memcmp(out, "h2", 2) == 0);
    }

    /* Client offers only http/1.1: no match. */
    {
        const unsigned char list[] = {8, 'h','t','t','p','/','1','.','1'};
        assert(magnus_h2_alpn_select_callback(NULL, &out, &outlen, list,
                                              sizeof(list), NULL)
               == SSL_TLSEXT_ERR_NOACK);
    }

    /* Empty list: no match, no crash. */
    assert(magnus_h2_alpn_select_callback(NULL, &out, &outlen, NULL, 0, NULL)
           == SSL_TLSEXT_ERR_NOACK);

    /* A 2-byte entry that merely contains "h2" as a substring of a
     * longer name must not match -- length-prefixed comparison, not a
     * substring search. "xh2" (length 3) followed by real "h2". */
    {
        const unsigned char list[] = {3, 'x','h','2', 2,'h','2'};
        assert(magnus_h2_alpn_select_callback(NULL, &out, &outlen, list,
                                              sizeof(list), NULL)
               == SSL_TLSEXT_ERR_OK);
        assert(outlen == 2);
        /* the match must be the *second* entry's bytes, not a slice of
         * the first */
        assert(out == list + 5);
    }

    /* Malformed list: a declared entry length that runs past the end of
     * the buffer. Must stop cleanly (no match, no out-of-bounds read),
     * not crash or read past `inlen`. */
    {
        const unsigned char list[] = {200, 'h', '2'};
        assert(magnus_h2_alpn_select_callback(NULL, &out, &outlen, list,
                                              sizeof(list), NULL)
               == SSL_TLSEXT_ERR_NOACK);
    }

    /* A zero-length entry followed by a real match: the zero-length
     * entry must not desync the scan. */
    {
        const unsigned char list[] = {0, 2, 'h', '2'};
        assert(magnus_h2_alpn_select_callback(NULL, &out, &outlen, list,
                                              sizeof(list), NULL)
               == SSL_TLSEXT_ERR_OK);
    }

    return 0;
}
