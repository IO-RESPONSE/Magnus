#include "magnus_uwsgi.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    /* Packet header: modifier1, little-endian 16-bit size, modifier2 --
     * the one place this protocol differs from FastCGI's own
     * big-endian convention. */
    {
        unsigned char buf[MAGNUS_UWSGI_HEADER_LEN];
        magnus_uwsgi_write_header(buf, 0, 0x0102, 0);
        assert(buf[0] == 0);
        assert(buf[1] == 0x02); /* low byte first (little-endian) */
        assert(buf[2] == 0x01);
        assert(buf[3] == 0);
    }

    /* Var encoding: 2-byte LE namelen + name + 2-byte LE valuelen +
     * value, no terminator of any kind. */
    {
        unsigned char buf[64];
        size_t n = magnus_uwsgi_encode_var("REQUEST_METHOD", "GET", buf,
                                           sizeof(buf));
        assert(n == 2 + 14 + 2 + 3);
        assert(buf[0] == 14 && buf[1] == 0);
        assert(memcmp(buf + 2, "REQUEST_METHOD", 14) == 0);
        assert(buf[16] == 3 && buf[17] == 0);
        assert(memcmp(buf + 18, "GET", 3) == 0);
    }

    /* Too small a buffer is rejected. */
    {
        unsigned char buf[4];
        assert(magnus_uwsgi_encode_var("REQUEST_METHOD", "GET", buf,
                                       sizeof(buf)) == 0);
    }

    /* Header translation: a real "HTTP/1.1 200 OK" first line (the
     * shape a real uWSGI server actually sends -- confirmed via direct
     * testing against uWSGI 2.0.31, see magnus_uwsgi.h's own top
     * comment) sets the real status, and is itself never passed
     * through as an ordinary header line. */
    {
        const char *hdrs = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                           "X-App: yes\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_uwsgi_translate_headers(hdrs, strlen(hdrs), 42, false,
                                               NULL, out, sizeof(out),
                                               &status);
        assert(n > 0);
        assert(status == 200);
        assert(strncmp(out, "HTTP/1.1 200 OK\r\n", 17) == 0);
        assert(strstr(out, "Content-Type: text/plain\r\n") != NULL);
        assert(strstr(out, "X-App: yes\r\n") != NULL);
        assert(strstr(out, "Content-Length: 42\r\n") != NULL);
        assert(strstr(out, "Connection: keep-alive\r\n") != NULL);
        assert(strstr(out, "X-Magnus-Via: magnus-uwsgi/0.1\r\n") != NULL);
        /* the real status line itself never leaks through as a literal
         * pass-through header a second time */
        assert(strstr(out + 17, "HTTP/1.1 200 OK") == NULL);
    }

    /* A non-200 status line. */
    {
        const char *hdrs = "HTTP/1.1 201 Created\r\nContent-Type: "
                           "text/plain\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_uwsgi_translate_headers(hdrs, strlen(hdrs), 8, true,
                                               NULL, out, sizeof(out),
                                               &status);
        assert(n > 0);
        assert(status == 201);
        assert(strncmp(out, "HTTP/1.1 201 Created\r\n", 22) == 0);
        assert(strstr(out, "Connection: close\r\n") != NULL);
    }

    /* No reason phrase -- defaults to "OK". */
    {
        const char *hdrs = "HTTP/1.1 404\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_uwsgi_translate_headers(hdrs, strlen(hdrs), 0, false,
                                               NULL, out, sizeof(out),
                                               &status);
        assert(n > 0);
        assert(status == 404);
        assert(strncmp(out, "HTTP/1.1 404 OK\r\n", 17) == 0);
    }

    /* A first line that is not HTTP-status-shaped at all falls back to
     * 200 OK (the same tolerant default magnus_fastcgi_translate_
     * headers() uses when no Status: line is present) -- this only
     * matters for a malformed/non-conforming application, since a real
     * uWSGI server always sends a real status line. */
    {
        const char *hdrs = "Content-Type: text/plain\r\nX-App: yes\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_uwsgi_translate_headers(hdrs, strlen(hdrs), 5, false,
                                               NULL, out, sizeof(out),
                                               &status);
        assert(n > 0);
        assert(status == 200);
        assert(strncmp(out, "HTTP/1.1 200 OK\r\n", 17) == 0);
        assert(strstr(out, "Content-Type: text/plain\r\n") != NULL);
        assert(strstr(out, "X-App: yes\r\n") != NULL);
    }

    /* affinity_cookie_value appends a Set-Cookie in the same format
     * every other dispatch path already uses. */
    {
        const char *hdrs = "HTTP/1.1 200 OK\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_uwsgi_translate_headers(hdrs, strlen(hdrs), 0, false,
                                               "05-abc123", out, sizeof(out),
                                               &status);
        assert(n > 0);
        assert(strstr(out,
            "Set-Cookie: MAGNUS_AFFINITY=05-abc123; Path=/; HttpOnly; "
            "SameSite=Lax\r\n") != NULL);
    }

    /* No affinity cookie -- no Set-Cookie at all. */
    {
        const char *hdrs = "HTTP/1.1 200 OK\r\n";
        char out[1024];
        unsigned status = 0;
        int n = magnus_uwsgi_translate_headers(hdrs, strlen(hdrs), 0, false,
                                               NULL, out, sizeof(out),
                                               &status);
        assert(n > 0);
        assert(strstr(out, "Set-Cookie:") == NULL);
    }

    /* Too-small an output buffer fails cleanly. */
    {
        const char *hdrs = "HTTP/1.1 200 OK\r\nX-App: yes\r\n";
        char out[8];
        unsigned status = 0;
        assert(magnus_uwsgi_translate_headers(hdrs, strlen(hdrs), 0, false,
                                              NULL, out, sizeof(out),
                                              &status) == -1);
    }

    printf("test-uwsgi: ok\n");
    return 0;
}
