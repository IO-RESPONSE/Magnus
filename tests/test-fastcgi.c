#include "magnus_fastcgi.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    /* Record header roundtrip. */
    {
        unsigned char buf[MAGNUS_FASTCGI_HEADER_LEN];
        unsigned char type;
        uint16_t request_id;
        size_t content_length;
        unsigned char padding_length;

        magnus_fastcgi_write_header(buf, MAGNUS_FASTCGI_STDOUT, 1, 4096);
        assert(buf[0] == MAGNUS_FASTCGI_VERSION);
        assert(buf[6] == 0 && buf[7] == 0); /* padding/reserved always 0 */
        assert(magnus_fastcgi_read_header(buf, &type, &request_id,
                                          &content_length, &padding_length));
        assert(type == MAGNUS_FASTCGI_STDOUT);
        assert(request_id == 1);
        assert(content_length == 4096);
        assert(padding_length == 0);

        /* A wrong version byte is rejected outright. */
        buf[0] = 9;
        assert(!magnus_fastcgi_read_header(buf, &type, &request_id,
                                           &content_length, &padding_length));
    }

    /* BEGIN_REQUEST body. */
    {
        unsigned char buf[8];
        magnus_fastcgi_write_begin_request_body(buf,
            MAGNUS_FASTCGI_ROLE_RESPONDER, 0);
        assert(buf[0] == 0 && buf[1] == 1); /* role, big-endian */
        assert(buf[2] == 0); /* flags */
        for (int i = 3; i < 8; i++) assert(buf[i] == 0);
    }

    /* Name-value encoding: short (1-byte length) form. */
    {
        unsigned char buf[64];
        size_t n = magnus_fastcgi_encode_nv("REQUEST_METHOD", "GET", buf,
                                            sizeof(buf));
        assert(n == 1 + 1 + 14 + 3);
        assert(buf[0] == 14); /* name length */
        assert(buf[1] == 3);  /* value length */
        assert(memcmp(buf + 2, "REQUEST_METHOD", 14) == 0);
        assert(memcmp(buf + 16, "GET", 3) == 0);
    }

    /* Name-value encoding: long (4-byte length, high bit set) form, once
     * a value is >= 128 bytes. */
    {
        unsigned char buf[512];
        char big[200];
        size_t n;
        memset(big, 'x', sizeof(big));
        big[sizeof(big) - 1] = '\0';
        n = magnus_fastcgi_encode_nv("V", big, buf, sizeof(buf));
        assert(n == 1 + 4 + 1 + (sizeof(big) - 1));
        assert(buf[0] == 1); /* name length, short form */
        assert((buf[1] & 0x80) != 0); /* value length, long form */
        assert(memcmp(buf + 1, "\x80\x00\x00\xc7", 4) == 0); /* 199 = 0xc7 */
    }

    /* Encoding fails cleanly (returns 0) when it would not fit. */
    {
        unsigned char buf[4];
        assert(magnus_fastcgi_encode_nv("REQUEST_METHOD", "GET", buf,
                                        sizeof(buf)) == 0);
    }

    /* Body boundary detection: \r\n\r\n. */
    {
        const char *data = "Status: 200 OK\r\nX-A: b\r\n\r\nBODY";
        size_t header_text_length;
        const char *body = magnus_fastcgi_find_body(data, strlen(data),
                                                     &header_text_length);
        assert(body != NULL);
        assert(header_text_length == strlen("Status: 200 OK\r\nX-A: b"));
        assert(strcmp(body, "BODY") == 0);
    }

    /* Body boundary detection: bare \n\n (some real applications only
     * ever send this). */
    {
        const char *data = "X-A: b\n\nBODY";
        size_t header_text_length;
        const char *body = magnus_fastcgi_find_body(data, strlen(data),
                                                     &header_text_length);
        assert(body != NULL);
        assert(header_text_length == strlen("X-A: b"));
        assert(strcmp(body, "BODY") == 0);
    }

    /* No blank line yet -- not malformed, just incomplete. */
    {
        const char *data = "X-A: b\r\nX-B: c\r\n";
        size_t header_text_length;
        assert(magnus_fastcgi_find_body(data, strlen(data),
                                        &header_text_length) == NULL);
    }

    /* Header translation: no Status: line defaults to 200 OK, an
     * application Content-Length/Connection/Status is discarded in
     * favor of what this function itself decides, and every other
     * header line passes through untouched. */
    {
        const char *headers =
            "Content-Type: text/html\r\n"
            "Status: 999\r\n" /* overwritten below by the real block */
            "X-App: yes\r\n";
        char out[1024];
        unsigned status = 0;
        int n;
        /* (deliberately not using the bogus Status: 999 above -- build a
         * clean no-Status block instead, tested separately below) */
        const char *clean = "Content-Type: text/html\r\nX-App: yes\r\n";
        n = magnus_fastcgi_translate_headers(clean, strlen(clean), 42, false,
                                             NULL, out, sizeof(out), &status);
        assert(n > 0);
        assert(status == 200);
        assert(strncmp(out, "HTTP/1.1 200 OK\r\n", 17) == 0);
        assert(strstr(out, "Content-Type: text/html\r\n") != NULL);
        assert(strstr(out, "X-App: yes\r\n") != NULL);
        assert(strstr(out, "Content-Length: 42\r\n") != NULL);
        assert(strstr(out, "Connection: keep-alive\r\n") != NULL);
        assert(strstr(out, "X-Magnus-Via: magnus-fastcgi/0.1\r\n") != NULL);
        assert(strstr(out, "Set-Cookie:") == NULL);
        (void) headers;
    }

    /* Header translation: a non-NULL affinity_cookie_value (roadmap
     * 5a-5) appends a Set-Cookie in the same format magnus_proxy_
     * sanitize_response_headers() already uses. */
    {
        const char *clean = "Content-Type: text/html\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_fastcgi_translate_headers(clean, strlen(clean), 0,
                                                 false, "05-abc123", out,
                                                 sizeof(out), &status);
        assert(n > 0);
        assert(strstr(out,
            "Set-Cookie: MAGNUS_AFFINITY=05-abc123; Path=/; HttpOnly; "
            "SameSite=Lax\r\n") != NULL);
    }

    /* Header translation: an explicit Status: line sets the real status
     * and reason, and is itself never passed through as an ordinary
     * header. Content-Length/Connection headers the application sent
     * are dropped in favor of the real, computed ones. */
    {
        const char *hdrs =
            "Status: 201 Created\r\n"
            "Content-Length: 999\r\n"
            "Connection: keep-alive\r\n"
            "X-App: yes\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_fastcgi_translate_headers(hdrs, strlen(hdrs), 3, true,
                                                  NULL, out, sizeof(out),
                                                  &status);
        assert(n > 0);
        assert(status == 201);
        assert(strncmp(out, "HTTP/1.1 201 Created\r\n", 22) == 0);
        assert(strstr(out, "Content-Length: 999") == NULL);
        assert(strstr(out, "Content-Length: 3\r\n") != NULL);
        assert(strstr(out, "Connection: close\r\n") != NULL);
        assert(strstr(out, "X-App: yes\r\n") != NULL);
    }

    /* Status: line with no reason phrase -- reason defaults to "OK". */
    {
        const char *hdrs = "Status: 404\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_fastcgi_translate_headers(hdrs, strlen(hdrs), 0, false,
                                                  NULL, out, sizeof(out),
                                                  &status);
        assert(n > 0);
        assert(status == 404);
        assert(strncmp(out, "HTTP/1.1 404 OK\r\n", 17) == 0);
    }

    /* A malformed Status: line's numeric code is rejected. */
    {
        const char *hdrs = "Status: not-a-number\r\n";
        char out[1024];
        unsigned status = 0;
        assert(magnus_fastcgi_translate_headers(hdrs, strlen(hdrs), 0, false,
                                                 NULL, out, sizeof(out),
                                                 &status) == -1);
    }

    /* Too-small an output buffer fails cleanly. */
    {
        const char *hdrs = "X-App: yes\r\n";
        char out[8];
        unsigned status = 0;
        assert(magnus_fastcgi_translate_headers(hdrs, strlen(hdrs), 0, false,
                                                 NULL, out, sizeof(out),
                                                 &status) == -1);
    }

    printf("test-fastcgi: ok\n");
    return 0;
}
