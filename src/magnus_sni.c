#include "magnus_sni.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

/* RFC 8446 5.1: TLSPlaintext.length must not exceed 2^14 (16384). Used
 * only as a sanity bound on the record-length field read off the wire --
 * this codebase's own caller-side peek buffer is smaller still, so a
 * record claiming to be larger than this is already unreachable in
 * practice, but checking the field itself (rather than trusting it)
 * matches this parser's own "never trust a length field past what it
 * proves" discipline. */
#define MAGNUS_SNI_MAX_RECORD_LENGTH 16384

static uint16_t
magnus_sni_read_u16(const unsigned char *data)
{
    return (uint16_t) ((data[0] << 8) | data[1]);
}

magnus_sni_result_t
magnus_sni_extract(const unsigned char *data, size_t length, char *out,
                   size_t out_capacity)
{
    size_t record_length;
    size_t handshake_length;
    const unsigned char *body;
    const unsigned char *cursor;
    const unsigned char *end;
    size_t session_id_length;
    size_t cipher_suites_length;
    size_t compression_methods_length;
    size_t extensions_length;
    const unsigned char *ext_end;

    /* Record header: content type (1) + legacy version (2) + length (2). */
    if (length < 5) return MAGNUS_SNI_INCOMPLETE;
    if (data[0] != 0x16) return MAGNUS_SNI_NOT_TLS; /* not a Handshake record */
    record_length = magnus_sni_read_u16(data + 3);
    if (record_length > MAGNUS_SNI_MAX_RECORD_LENGTH) return MAGNUS_SNI_MALFORMED;
    if (length < 5 + record_length) return MAGNUS_SNI_INCOMPLETE;

    /* Handshake header, within the record body: msg type (1) + length (3). */
    if (record_length < 4) return MAGNUS_SNI_MALFORMED;
    body = data + 5;
    if (body[0] != 0x01) return MAGNUS_SNI_MALFORMED; /* not a ClientHello */
    handshake_length = ((size_t) body[1] << 16) | ((size_t) body[2] << 8)
                       | (size_t) body[3];
    /* A ClientHello that does not fit in this one record is a real (if
     * rare) case this parser deliberately does not stitch back together
     * -- see this function's own header comment. Reported the same way
     * as "have not received enough bytes yet" since, from the caller's
     * perspective watching one growing buffer, it looks identical. */
    if (4 + handshake_length > record_length) return MAGNUS_SNI_INCOMPLETE;

    cursor = body + 4;
    end = cursor + handshake_length;

    /* client_version (2) + random (32). */
    if ((size_t) (end - cursor) < 34) return MAGNUS_SNI_MALFORMED;
    cursor += 34;

    /* session_id: 1-byte length prefix. */
    if (cursor >= end) return MAGNUS_SNI_MALFORMED;
    session_id_length = *cursor;
    cursor += 1;
    if ((size_t) (end - cursor) < session_id_length) return MAGNUS_SNI_MALFORMED;
    cursor += session_id_length;

    /* cipher_suites: 2-byte length prefix. */
    if ((size_t) (end - cursor) < 2) return MAGNUS_SNI_MALFORMED;
    cipher_suites_length = magnus_sni_read_u16(cursor);
    cursor += 2;
    if ((size_t) (end - cursor) < cipher_suites_length) return MAGNUS_SNI_MALFORMED;
    cursor += cipher_suites_length;

    /* compression_methods: 1-byte length prefix. */
    if (cursor >= end) return MAGNUS_SNI_MALFORMED;
    compression_methods_length = *cursor;
    cursor += 1;
    if ((size_t) (end - cursor) < compression_methods_length)
        return MAGNUS_SNI_MALFORMED;
    cursor += compression_methods_length;

    /* No extensions field at all is a legal (if now essentially extinct)
     * ClientHello shape -- nothing malformed about it, just nothing to
     * route on. */
    if (cursor == end) return MAGNUS_SNI_NO_SNI;
    if ((size_t) (end - cursor) < 2) return MAGNUS_SNI_MALFORMED;
    extensions_length = magnus_sni_read_u16(cursor);
    cursor += 2;
    if ((size_t) (end - cursor) < extensions_length) return MAGNUS_SNI_MALFORMED;
    ext_end = cursor + extensions_length;

    while (cursor < ext_end) {
        uint16_t ext_type;
        size_t ext_length;
        const unsigned char *ext_data;

        if ((size_t) (ext_end - cursor) < 4) return MAGNUS_SNI_MALFORMED;
        ext_type = magnus_sni_read_u16(cursor);
        cursor += 2;
        ext_length = magnus_sni_read_u16(cursor);
        cursor += 2;
        if ((size_t) (ext_end - cursor) < ext_length) return MAGNUS_SNI_MALFORMED;
        ext_data = cursor;

        if (ext_type == 0) {
            /* server_name extension (RFC 6066 3): a 2-byte
             * ServerNameList length, then a list of (1-byte name_type,
             * 2-byte length, name) entries. Only name_type 0 (host_name)
             * is defined; a real ClientHello carries exactly one entry,
             * but the format technically allows more, so a non-host_name
             * entry is skipped rather than treated as malformed. */
            const unsigned char *list_cursor;
            const unsigned char *list_end;
            size_t list_length;

            if (ext_length < 2) return MAGNUS_SNI_MALFORMED;
            list_length = magnus_sni_read_u16(ext_data);
            if (list_length > ext_length - 2) return MAGNUS_SNI_MALFORMED;
            list_cursor = ext_data + 2;
            list_end = list_cursor + list_length;

            while (list_cursor < list_end) {
                unsigned char name_type;
                size_t name_length;

                if ((size_t) (list_end - list_cursor) < 3)
                    return MAGNUS_SNI_MALFORMED;
                name_type = list_cursor[0];
                name_length = magnus_sni_read_u16(list_cursor + 1);
                list_cursor += 3;
                if ((size_t) (list_end - list_cursor) < name_length)
                    return MAGNUS_SNI_MALFORMED;
                if (name_type == 0) {
                    size_t i;
                    if (name_length == 0 || name_length >= out_capacity)
                        return MAGNUS_SNI_MALFORMED;
                    for (i = 0; i < name_length; i++) {
                        out[i] = (char) tolower(list_cursor[i]);
                    }
                    out[name_length] = '\0';
                    return MAGNUS_SNI_OK;
                }
                list_cursor += name_length;
            }
            /* A server_name extension with no host_name entry inside it
             * -- nothing else in the ClientHello could change that, so
             * there is no reason to keep scanning further extensions. */
            return MAGNUS_SNI_NO_SNI;
        }

        cursor += ext_length;
    }
    return MAGNUS_SNI_NO_SNI;
}

bool
magnus_sni_pattern_matches(const char *pattern, const char *hostname)
{
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1; /* leading "." kept */
        size_t suffix_length = strlen(suffix);
        size_t hostname_length = strlen(hostname);
        if (hostname_length <= suffix_length) return false;
        return strcasecmp(hostname + (hostname_length - suffix_length), suffix)
               == 0;
    }
    return strcasecmp(pattern, hostname) == 0;
}
