#include "magnus_realip.h"
#include "magnus_config.h"
#include "magnus_http.h"
#include "magnus_route.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void
set_header(magnus_http_request_t *request, const char *name, const char *value)
{
    assert(request->header_count < MAGNUS_HTTP_MAX_HEADERS);
    magnus_http_header_t *h = &request->headers[request->header_count++];
    strcpy(h->name, name);
    strcpy(h->value, value);
}

int
main(void)
{
    /* --- 1. CIDR Matching --- */
    {
        magnus_cidr_t trusted[2];
        assert(magnus_route_parse_cidr("10.0.0.0/8", &trusted[0].network, &trusted[0].prefix_length));
        assert(magnus_route_parse_cidr("172.16.0.0/12", &trusted[1].network, &trusted[1].prefix_length));

        struct in_addr ip_in_10, ip_in_172, ip_outside;
        inet_pton(AF_INET, "10.1.2.3", &ip_in_10);
        inet_pton(AF_INET, "172.20.5.6", &ip_in_172);
        inet_pton(AF_INET, "192.168.1.1", &ip_outside);

        assert(magnus_realip_is_trusted(trusted, 2, ip_in_10));
        assert(magnus_realip_is_trusted(trusted, 2, ip_in_172));
        assert(!magnus_realip_is_trusted(trusted, 2, ip_outside));
        assert(!magnus_realip_is_trusted(NULL, 0, ip_in_10));
    }

    /* --- 2. X-Forwarded-For Resolution --- */
    {
        magnus_cidr_t trusted[2];
        assert(magnus_route_parse_cidr("10.0.0.0/8", &trusted[0].network, &trusted[0].prefix_length));
        assert(magnus_route_parse_cidr("127.0.0.1/32", &trusted[1].network, &trusted[1].prefix_length));

        magnus_http_request_t req;
        struct in_addr resolved;
        char ip_str[INET_ADDRSTRLEN];

        /* Single untrusted hop */
        memset(&req, 0, sizeof(req));
        set_header(&req, "X-Forwarded-For", "203.0.113.195");
        assert(magnus_realip_resolve_headers(&req, trusted, 2, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "203.0.113.195") == 0);

        /* Untrusted client, trusted proxy: walk right-to-left */
        memset(&req, 0, sizeof(req));
        set_header(&req, "X-Forwarded-For", "203.0.113.195, 10.0.0.2");
        assert(magnus_realip_resolve_headers(&req, trusted, 2, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "203.0.113.195") == 0);

        /* Spoofing defense: spoofed 1.1.1.1, real client 203.0.113.195, LB 10.0.0.2 */
        memset(&req, 0, sizeof(req));
        set_header(&req, "X-Forwarded-For", "1.1.1.1, 203.0.113.195, 10.0.0.2");
        assert(magnus_realip_resolve_headers(&req, trusted, 2, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "203.0.113.195") == 0);

        /* IP with port */
        memset(&req, 0, sizeof(req));
        set_header(&req, "X-Forwarded-For", "203.0.113.50:443, 10.0.0.2:8080");
        assert(magnus_realip_resolve_headers(&req, trusted, 2, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "203.0.113.50") == 0);

        /* All trusted hops -> returns leftmost candidate */
        memset(&req, 0, sizeof(req));
        set_header(&req, "X-Forwarded-For", "10.0.0.1, 10.0.0.2");
        assert(magnus_realip_resolve_headers(&req, trusted, 2, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "10.0.0.1") == 0);
    }

    /* --- 3. Forwarded (RFC 7239) Resolution --- */
    {
        magnus_cidr_t trusted[1];
        assert(magnus_route_parse_cidr("10.0.0.0/8", &trusted[0].network, &trusted[0].prefix_length));

        magnus_http_request_t req;
        struct in_addr resolved;
        char ip_str[INET_ADDRSTRLEN];

        /* Plain Forwarded */
        memset(&req, 0, sizeof(req));
        set_header(&req, "Forwarded", "for=198.51.100.17;proto=http;by=10.0.0.1, for=10.0.0.2");
        assert(magnus_realip_resolve_headers(&req, trusted, 1, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "198.51.100.17") == 0);

        /* Quoted Forwarded with port */
        memset(&req, 0, sizeof(req));
        set_header(&req, "Forwarded", "for=\"198.51.100.22:1234\", for=\"10.0.0.5\"");
        assert(magnus_realip_resolve_headers(&req, trusted, 1, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "198.51.100.22") == 0);

        /* Precedence: Forwarded wins over X-Forwarded-For */
        memset(&req, 0, sizeof(req));
        set_header(&req, "Forwarded", "for=198.51.100.99");
        set_header(&req, "X-Forwarded-For", "203.0.113.88");
        assert(magnus_realip_resolve_headers(&req, trusted, 1, &resolved));
        inet_ntop(AF_INET, &resolved, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "198.51.100.99") == 0);
    }

    /* --- 4. PROXY Protocol v1 (Text) --- */
    {
        size_t consumed = 0;
        struct in_addr src_ip = {0};
        char ip_str[INET_ADDRSTRLEN];
        magnus_proxy_proto_result_t res;

        const char *v1_valid = "PROXY TCP4 192.168.1.100 10.0.0.1 54321 80\r\nGET / HTTP/1.1\r\n";
        res = magnus_proxy_proto_parse(v1_valid, strlen(v1_valid), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_OK);
        assert(consumed == strlen("PROXY TCP4 192.168.1.100 10.0.0.1 54321 80\r\n"));
        inet_ntop(AF_INET, &src_ip, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "192.168.1.100") == 0);

        /* PROXY UNKNOWN */
        const char *v1_unknown = "PROXY UNKNOWN\r\n";
        consumed = 0;
        src_ip.s_addr = 0x12345678;
        res = magnus_proxy_proto_parse(v1_unknown, strlen(v1_unknown), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_OK);
        assert(consumed == strlen(v1_unknown));
        assert(src_ip.s_addr == 0x12345678);

        /* Incomplete v1 */
        const char *v1_inc = "PROXY TCP4 192.168.1.100";
        res = magnus_proxy_proto_parse(v1_inc, strlen(v1_inc), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_INCOMPLETE);

        /* Malformed v1: invalid IP */
        const char *v1_bad_ip = "PROXY TCP4 999.999.999.999 10.0.0.1 1 2\r\n";
        res = magnus_proxy_proto_parse(v1_bad_ip, strlen(v1_bad_ip), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_ERROR);

        /* Malformed v1: missing fields */
        const char *v1_missing = "PROXY TCP4 10.0.0.1 10.0.0.2\r\n";
        res = magnus_proxy_proto_parse(v1_missing, strlen(v1_missing), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_ERROR);
    }

    /* --- 5. PROXY Protocol v2 (Binary) --- */
    {
        size_t consumed = 0;
        struct in_addr src_ip = {0};
        char ip_str[INET_ADDRSTRLEN];
        magnus_proxy_proto_result_t res;

        /* Valid v2 PROXY AF_INET STREAM */
        unsigned char v2_packet[28] = {
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            0x21, /* ver 2, cmd PROXY */
            0x11, /* AF_INET, STREAM */
            0x00, 0x0C, /* length 12 */
            192, 168, 50, 75, /* src_ip: 192.168.50.75 */
            10, 0, 0, 1,      /* dst_ip: 10.0.0.1 */
            0x1F, 0x90,       /* src_port: 8080 */
            0x00, 0x50        /* dst_port: 80 */
        };

        res = magnus_proxy_proto_parse((const char *) v2_packet, sizeof(v2_packet), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_OK);
        assert(consumed == 28);
        inet_ntop(AF_INET, &src_ip, ip_str, sizeof(ip_str));
        assert(strcmp(ip_str, "192.168.50.75") == 0);

        /* Valid v2 LOCAL */
        unsigned char v2_local[16] = {
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            0x20, /* ver 2, cmd LOCAL */
            0x00, /* AF_UNSPEC */
            0x00, 0x00
        };
        src_ip.s_addr = 0x87654321;
        res = magnus_proxy_proto_parse((const char *) v2_local, sizeof(v2_local), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_OK);
        assert(consumed == 16);
        assert(src_ip.s_addr == 0x87654321);

        /* Incomplete v2 */
        res = magnus_proxy_proto_parse((const char *) v2_packet, 20, &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_INCOMPLETE);

        /* Malformed version */
        v2_packet[12] = 0x11; /* ver 1 */
        res = magnus_proxy_proto_parse((const char *) v2_packet, sizeof(v2_packet), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_ERROR);
    }

    /* --- 6. Non-PROXY Streams --- */
    {
        size_t consumed = 0;
        struct in_addr src_ip = {0};
        magnus_proxy_proto_result_t res;

        const char *http_get = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        res = magnus_proxy_proto_parse(http_get, strlen(http_get), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_NOT_PROXY);

        const char *http_post = "POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        res = magnus_proxy_proto_parse(http_post, strlen(http_post), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_NOT_PROXY);

        const unsigned char tls_client_hello[] = { 0x16, 0x03, 0x01, 0x00, 0xA0 };
        res = magnus_proxy_proto_parse((const char *) tls_client_hello, sizeof(tls_client_hello), &consumed, &src_ip);
        assert(res == MAGNUS_PROXY_PROTO_NOT_PROXY);
    }

    printf("test-realip: ok\n");
    return 0;
}
