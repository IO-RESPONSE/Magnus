#include "magnus_realip.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char MAGNUS_PROXY_V1_SIG[] = "PROXY ";
static const unsigned char MAGNUS_PROXY_V2_SIG[] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

bool
magnus_realip_is_trusted(const magnus_cidr_t *trusted, size_t count,
                         struct in_addr ip)
{
    if (trusted == NULL || count == 0) return false;
    for (size_t i = 0; i < count; i++) {
        uint32_t mask = trusted[i].prefix_length == 0
            ? 0 : htonl(0xFFFFFFFFu << (32 - trusted[i].prefix_length));
        if ((ip.s_addr & mask) == (trusted[i].network.s_addr & mask))
            return true;
    }
    return false;
}

/* Parses an IP string token into a struct in_addr.
 * Handles:
 *   "1.2.3.4"
 *   "\"1.2.3.4\"" (quoted)
 *   "1.2.3.4:8080" (with port)
 *   "\"1.2.3.4:8080\"" (quoted with port)
 *   "[1.2.3.4]:8080" (IPv4 in brackets with port)
 * Returns true on successful IPv4 parse, false otherwise.
 */
static bool
magnus_parse_ip_token(const char *token, size_t token_len, struct in_addr *out_ip)
{
    char buf[64];
    const char *start = token;
    const char *end = token + token_len;

    while (start < end && (*start == ' ' || *start == '\t' || *start == '"'))
        start++;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '"'))
        end--;

    if (start >= end) return false;

    size_t len = (size_t) (end - start);
    if (len >= sizeof(buf)) return false;
    memcpy(buf, start, len);
    buf[len] = '\0';

    /* Handle [ip] or [ip]:port */
    if (buf[0] == '[') {
        char *close_bracket = strchr(buf, ']');
        if (close_bracket == NULL) return false;
        *close_bracket = '\0';
        return inet_pton(AF_INET, buf + 1, out_ip) == 1;
    }

    /* Handle ip:port (only if single colon and all digits after colon) */
    char *colon = strchr(buf, ':');
    if (colon != NULL) {
        /* Check if there's a second colon (IPv6 address literal) */
        if (strchr(colon + 1, ':') != NULL) return false;
        char *port_scan = colon + 1;
        if (*port_scan == '\0') return false;
        while (*port_scan != '\0') {
            if (!isdigit((unsigned char) *port_scan)) return false;
            port_scan++;
        }
        *colon = '\0';
    }

    return inet_pton(AF_INET, buf, out_ip) == 1;
}

/* Resolves Real IP from X-Forwarded-For header value, walking from right to left. */
static bool
magnus_realip_resolve_xff(const char *header_val,
                          const magnus_cidr_t *trusted, size_t count,
                          struct in_addr *out_real_ip)
{
    size_t len = strlen(header_val);
    const char *cursor = header_val + len;
    struct in_addr candidate = {0};
    bool found_candidate = false;

    while (cursor > header_val) {
        const char *token_end = cursor;
        while (cursor > header_val && cursor[-1] != ',') cursor--;
        const char *token_start = cursor;
        size_t token_len = (size_t) (token_end - token_start);

        struct in_addr parsed_ip;
        if (magnus_parse_ip_token(token_start, token_len, &parsed_ip)) {
            if (!magnus_realip_is_trusted(trusted, count, parsed_ip)) {
                *out_real_ip = parsed_ip;
                return true;
            }
            candidate = parsed_ip;
            found_candidate = true;
        }

        if (cursor > header_val && cursor[-1] == ',')
            cursor--;
    }

    if (found_candidate) {
        *out_real_ip = candidate;
        return true;
    }
    return false;
}

/* Resolves Real IP from Forwarded (RFC 7239) header value, walking from right to left. */
static bool
magnus_realip_resolve_forwarded(const char *header_val,
                                const magnus_cidr_t *trusted, size_t count,
                                struct in_addr *out_real_ip)
{
    size_t len = strlen(header_val);
    const char *cursor = header_val + len;
    struct in_addr candidate = {0};
    bool found_candidate = false;

    while (cursor > header_val) {
        const char *elem_end = cursor;
        while (cursor > header_val && cursor[-1] != ',') cursor--;
        const char *elem_start = cursor;

        /* Find "for=" in elem */
        const char *scan = elem_start;
        const char *stop = elem_end;
        while (scan + 4 <= stop) {
            bool is_param_start = (scan == elem_start || scan[-1] == ';'
                                   || scan[-1] == ' ' || scan[-1] == '\t');
            if (is_param_start && strncasecmp(scan, "for=", 4) == 0) {
                const char *val_start = scan + 4;
                const char *val_end = val_start;
                while (val_end < stop && *val_end != ';' && *val_end != ' '
                       && *val_end != '\t') {
                    if (*val_end == '"') {
                        val_end++;
                        while (val_end < stop && *val_end != '"') {
                            if (*val_end == '\\' && val_end + 1 < stop) val_end++;
                            val_end++;
                        }
                        if (val_end < stop && *val_end == '"') val_end++;
                    } else {
                        val_end++;
                    }
                }

                struct in_addr parsed_ip;
                if (magnus_parse_ip_token(val_start, (size_t) (val_end - val_start),
                                          &parsed_ip)) {
                    if (!magnus_realip_is_trusted(trusted, count, parsed_ip)) {
                        *out_real_ip = parsed_ip;
                        return true;
                    }
                    candidate = parsed_ip;
                    found_candidate = true;
                }
                break;
            }
            scan++;
        }

        if (cursor > header_val && cursor[-1] == ',')
            cursor--;
    }

    if (found_candidate) {
        *out_real_ip = candidate;
        return true;
    }
    return false;
}

bool
magnus_realip_resolve_headers(const magnus_http_request_t *request,
                              const magnus_cidr_t *trusted, size_t count,
                              struct in_addr *out_real_ip)
{
    const char *fwd = magnus_http_header_find(request, "forwarded");
    if (fwd != NULL && magnus_realip_resolve_forwarded(fwd, trusted, count, out_real_ip)) {
        return true;
    }

    const char *xff = magnus_http_header_find(request, "x-forwarded-for");
    if (xff != NULL && magnus_realip_resolve_xff(xff, trusted, count, out_real_ip)) {
        return true;
    }

    return false;
}

magnus_proxy_proto_result_t
magnus_proxy_proto_parse(const char *buffer, size_t length,
                         size_t *out_consumed, struct in_addr *out_src_ip)
{
    if (length == 0) return MAGNUS_PROXY_PROTO_INCOMPLETE;

    bool could_be_v1 = (length < 6)
        ? (memcmp(buffer, MAGNUS_PROXY_V1_SIG, length) == 0)
        : (memcmp(buffer, MAGNUS_PROXY_V1_SIG, 6) == 0);

    bool could_be_v2 = (length < 12)
        ? (memcmp(buffer, MAGNUS_PROXY_V2_SIG, length) == 0)
        : (memcmp(buffer, MAGNUS_PROXY_V2_SIG, 12) == 0);

    if (!could_be_v1 && !could_be_v2) {
        return MAGNUS_PROXY_PROTO_NOT_PROXY;
    }

    if (could_be_v1) {
        if (length < 6) return MAGNUS_PROXY_PROTO_INCOMPLETE;

        /* Max PROXY v1 line length is 107 bytes including \r\n */
        size_t scan_limit = length < 107 ? length : 107;
        const char *crlf = NULL;
        for (size_t i = 0; i + 1 < scan_limit; i++) {
            if (buffer[i] == '\r' && buffer[i + 1] == '\n') {
                crlf = buffer + i;
                break;
            }
        }

        if (crlf == NULL) {
            if (length >= 107) return MAGNUS_PROXY_PROTO_ERROR;
            return MAGNUS_PROXY_PROTO_INCOMPLETE;
        }

        size_t line_len = (size_t) (crlf - buffer) + 2;
        char line[108];
        memcpy(line, buffer, line_len);
        line[line_len] = '\0';

        char *saveptr = NULL;
        char *token_proxy = strtok_r(line, " \r\n", &saveptr);
        char *token_proto = strtok_r(NULL, " \r\n", &saveptr);

        if (token_proxy == NULL || strcmp(token_proxy, "PROXY") != 0
            || token_proto == NULL) {
            return MAGNUS_PROXY_PROTO_ERROR;
        }

        if (strcmp(token_proto, "UNKNOWN") == 0) {
            *out_consumed = line_len;
            return MAGNUS_PROXY_PROTO_OK;
        }

        if (strcmp(token_proto, "TCP4") == 0) {
            char *token_src = strtok_r(NULL, " \r\n", &saveptr);
            char *token_dst = strtok_r(NULL, " \r\n", &saveptr);
            char *token_sport = strtok_r(NULL, " \r\n", &saveptr);
            char *token_dport = strtok_r(NULL, " \r\n", &saveptr);
            char *token_extra = strtok_r(NULL, " \r\n", &saveptr);

            if (token_src == NULL || token_dst == NULL || token_sport == NULL
                || token_dport == NULL || token_extra != NULL) {
                return MAGNUS_PROXY_PROTO_ERROR;
            }

            struct in_addr src_addr;
            struct in_addr dst_addr;
            if (inet_pton(AF_INET, token_src, &src_addr) != 1) {
                return MAGNUS_PROXY_PROTO_ERROR;
            }
            if (inet_pton(AF_INET, token_dst, &dst_addr) != 1) {
                return MAGNUS_PROXY_PROTO_ERROR;
            }

            char *endptr;
            unsigned long sport = strtoul(token_sport, &endptr, 10);
            if (*endptr != '\0' || sport == 0 || sport > 65535) {
                return MAGNUS_PROXY_PROTO_ERROR;
            }
            unsigned long dport = strtoul(token_dport, &endptr, 10);
            if (*endptr != '\0' || dport == 0 || dport > 65535) {
                return MAGNUS_PROXY_PROTO_ERROR;
            }

            *out_consumed = line_len;
            *out_src_ip = src_addr;
            return MAGNUS_PROXY_PROTO_OK;
        }

        if (strcmp(token_proto, "TCP6") == 0) {
            /* Valid format according to spec; preserve peer address in IPv4 engine */
            *out_consumed = line_len;
            return MAGNUS_PROXY_PROTO_OK;
        }

        return MAGNUS_PROXY_PROTO_ERROR;
    }

    if (could_be_v2) {
        if (length < 16) return MAGNUS_PROXY_PROTO_INCOMPLETE;

        uint8_t ver_cmd = (uint8_t) buffer[12];
        uint8_t fam_proto = (uint8_t) buffer[13];
        uint16_t addr_len = (((uint8_t) buffer[14]) << 8) | ((uint8_t) buffer[15]);

        if ((ver_cmd & 0xF0) != 0x20) {
            return MAGNUS_PROXY_PROTO_ERROR;
        }
        if (addr_len > 1024) {
            return MAGNUS_PROXY_PROTO_ERROR;
        }

        size_t total_len = 16 + addr_len;
        if (length < total_len) {
            return MAGNUS_PROXY_PROTO_INCOMPLETE;
        }

        uint8_t cmd = ver_cmd & 0x0F;
        if (cmd == 0x00) {
            /* LOCAL command: connection established on proxy's own initiative */
            *out_consumed = total_len;
            return MAGNUS_PROXY_PROTO_OK;
        }

        if (cmd == 0x01) {
            /* PROXY command */
            uint8_t fam = fam_proto & 0xF0;
            if (fam == 0x10) {
                /* AF_INET */
                if (addr_len < 12) {
                    return MAGNUS_PROXY_PROTO_ERROR;
                }
                memcpy(out_src_ip, buffer + 16, 4);
                *out_consumed = total_len;
                return MAGNUS_PROXY_PROTO_OK;
            }
            if (fam == 0x00 || fam == 0x20 || fam == 0x30) {
                /* UNSPEC, AF_INET6, AF_UNIX: valid in v2 spec */
                *out_consumed = total_len;
                return MAGNUS_PROXY_PROTO_OK;
            }
            return MAGNUS_PROXY_PROTO_ERROR;
        }

        return MAGNUS_PROXY_PROTO_ERROR;
    }

    return MAGNUS_PROXY_PROTO_NOT_PROXY;
}

size_t
magnus_proxy_proto_build(magnus_proxy_protocol_mode_t mode,
                         struct in_addr src_addr, uint16_t src_port,
                         struct in_addr dst_addr, uint16_t dst_port,
                         unsigned char *out, size_t out_capacity)
{
    if (mode == MAGNUS_PROXY_PROTOCOL_V1) {
        /* "PROXY TCP4 " (11) + up to 15 + " " + up to 15 + " " + up to 5
         * + " " + up to 5 + "\r\n" (2) = 56 bytes worst case, well under
         * MAGNUS_PROXY_PROTO_BUILD_MAX. Ports are printed as plain host-
         * order decimal, exactly what "%u" already expects. */
        char src_text[INET_ADDRSTRLEN];
        char dst_text[INET_ADDRSTRLEN];
        int length;
        if (inet_ntop(AF_INET, &src_addr, src_text, sizeof(src_text)) == NULL
            || inet_ntop(AF_INET, &dst_addr, dst_text, sizeof(dst_text)) == NULL)
            return 0;
        length = snprintf((char *) out, out_capacity,
                          "PROXY TCP4 %s %s %u %u\r\n",
                          src_text, dst_text, src_port, dst_port);
        if (length <= 0 || (size_t) length >= out_capacity) return 0;
        return (size_t) length;
    }
    if (mode == MAGNUS_PROXY_PROTOCOL_V2) {
        /* Fixed 28-byte layout for TCP-over-IPv4 (RFC-less, but this is
         * the widely-implemented HAProxy PROXY protocol v2 spec): the
         * same 12-byte signature magnus_proxy_proto_parse() above
         * already recognizes on the receiving side, then version+command
         * (0x21 = v2, PROXY), address-family+transport (0x11 = AF_INET,
         * STREAM), a 2-byte big-endian address-block length (12), and
         * the address block itself (src addr, dst addr, src port, dst
         * port -- ports in network byte order on the wire, per spec,
         * hence the explicit htons() here even though this function's
         * own parameters are host order). */
        uint16_t src_port_be = htons(src_port);
        uint16_t dst_port_be = htons(dst_port);
        if (out_capacity < 28) return 0;
        memcpy(out, MAGNUS_PROXY_V2_SIG, 12);
        out[12] = 0x21;
        out[13] = 0x11;
        out[14] = 0x00;
        out[15] = 12;
        memcpy(out + 16, &src_addr, 4);
        memcpy(out + 20, &dst_addr, 4);
        memcpy(out + 24, &src_port_be, 2);
        memcpy(out + 26, &dst_port_be, 2);
        return 28;
    }
    return 0;
}
