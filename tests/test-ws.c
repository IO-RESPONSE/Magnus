#include "magnus_ws.h"

#include <assert.h>
#include <string.h>

int
main(void)
{
    magnus_ws_frame_header_t header;
    unsigned char frame[32];

    /* Minimal unmasked text frame, fin=1, 5-byte payload ("hello"): 81 05. */
    memcpy(frame, (unsigned char[]) {0x81, 0x05}, 2);
    assert(magnus_ws_parse_header(frame, 2, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.fin);
    assert(header.opcode == MAGNUS_WS_OPCODE_TEXT);
    assert(!header.masked);
    assert(header.payload_length == 5);
    assert(header.header_length == 2);
    assert(magnus_ws_mask_direction_ok(&header, false));
    assert(!magnus_ws_mask_direction_ok(&header, true));

    /* Same frame, but only the first byte present: incomplete. */
    assert(magnus_ws_parse_header(frame, 1, &header) == MAGNUS_WS_HEADER_INCOMPLETE);
    assert(magnus_ws_parse_header(frame, 0, &header) == MAGNUS_WS_HEADER_INCOMPLETE);

    /* Masked binary frame, fin=1, 5-byte payload, mask key AA BB CC DD:
     * 82 85 AA BB CC DD. */
    memcpy(frame, (unsigned char[]) {0x82, 0x85, 0xAA, 0xBB, 0xCC, 0xDD}, 6);
    assert(magnus_ws_parse_header(frame, 6, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.opcode == MAGNUS_WS_OPCODE_BINARY);
    assert(header.masked);
    assert(header.payload_length == 5);
    assert(header.header_length == 6);
    assert(memcmp(header.mask_key, "\xAA\xBB\xCC\xDD", 4) == 0);
    assert(magnus_ws_mask_direction_ok(&header, true));
    assert(!magnus_ws_mask_direction_ok(&header, false));
    /* Mask key not fully present yet: incomplete, not a short payload. */
    assert(magnus_ws_parse_header(frame, 5, &header) == MAGNUS_WS_HEADER_INCOMPLETE);

    /* 16-bit extended length: 200 bytes, unmasked binary, fin=1:
     * 82 7E 00 C8. */
    memcpy(frame, (unsigned char[]) {0x82, 0x7E, 0x00, 0xC8}, 4);
    assert(magnus_ws_parse_header(frame, 4, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.payload_length == 200);
    assert(header.header_length == 4);
    assert(magnus_ws_parse_header(frame, 3, &header) == MAGNUS_WS_HEADER_INCOMPLETE);

    /* 16-bit extended length that could have fit in 7 bits (125): must
     * use minimal encoding -- invalid, not merely inefficient. */
    memcpy(frame, (unsigned char[]) {0x82, 0x7E, 0x00, 0x7D}, 4);
    assert(magnus_ws_parse_header(frame, 4, &header) == MAGNUS_WS_HEADER_INVALID);

    /* 64-bit extended length: 100000 bytes. */
    memcpy(frame, (unsigned char[]) {
        0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xA0
    }, 10);
    assert(magnus_ws_parse_header(frame, 10, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.payload_length == 100000);
    assert(header.header_length == 10);

    /* 64-bit extended length that could have fit in 16 bits: invalid. */
    memcpy(frame, (unsigned char[]) {
        0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
    }, 10);
    assert(magnus_ws_parse_header(frame, 10, &header) == MAGNUS_WS_HEADER_INVALID);

    /* 64-bit length with the high bit set: invalid regardless of value. */
    memcpy(frame, (unsigned char[]) {
        0x82, 0x7F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }, 10);
    assert(magnus_ws_parse_header(frame, 10, &header) == MAGNUS_WS_HEADER_INVALID);

    /* Reserved bits set: invalid (no extension is ever negotiated). */
    memcpy(frame, (unsigned char[]) {0xF1, 0x00}, 2);
    assert(magnus_ws_parse_header(frame, 2, &header) == MAGNUS_WS_HEADER_INVALID);

    /* Undefined opcode (0x3, reserved for future non-control frames):
     * invalid. */
    memcpy(frame, (unsigned char[]) {0x83, 0x00}, 2);
    assert(magnus_ws_parse_header(frame, 2, &header) == MAGNUS_WS_HEADER_INVALID);

    /* Undefined opcode (0xB, reserved for future control frames):
     * invalid. */
    memcpy(frame, (unsigned char[]) {0x8B, 0x00}, 2);
    assert(magnus_ws_parse_header(frame, 2, &header) == MAGNUS_WS_HEADER_INVALID);

    /* Control frame (ping) fragmented (fin=0): invalid. */
    memcpy(frame, (unsigned char[]) {0x09, 0x00}, 2);
    assert(magnus_ws_parse_header(frame, 2, &header) == MAGNUS_WS_HEADER_INVALID);

    /* Control frame (close) with payload over 125 bytes: invalid. */
    memcpy(frame, (unsigned char[]) {0x88, 0x7E, 0x00, 0x7E}, 4);
    assert(magnus_ws_parse_header(frame, 4, &header) == MAGNUS_WS_HEADER_INVALID);

    /* Valid close frame with a 2-byte status-code payload: fine. */
    memcpy(frame, (unsigned char[]) {0x88, 0x02, 0x03, 0xE8}, 4);
    assert(magnus_ws_parse_header(frame, 4, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.opcode == MAGNUS_WS_OPCODE_CLOSE);
    assert(header.payload_length == 2);

    /* Ping/pong with zero-length payload, unmasked (server-originated
     * keepalive is a normal case even though this codebase does not send
     * one itself yet): fine. */
    memcpy(frame, (unsigned char[]) {0x89, 0x00}, 2);
    assert(magnus_ws_parse_header(frame, 2, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.opcode == MAGNUS_WS_OPCODE_PING);
    assert(header.payload_length == 0);
    memcpy(frame, (unsigned char[]) {0x8A, 0x80, 0x00, 0x00, 0x00, 0x00}, 6);
    assert(magnus_ws_parse_header(frame, 6, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.opcode == MAGNUS_WS_OPCODE_PONG);
    assert(header.masked);
    assert(header.payload_length == 0);

    /* A continuation frame (fragmentation) parses like any other data
     * frame at the header level -- this module does not track
     * fragmentation state, since the relay does not need to. */
    memcpy(frame, (unsigned char[]) {0x00, 0x05}, 2);
    assert(magnus_ws_parse_header(frame, 2, &header) == MAGNUS_WS_HEADER_OK);
    assert(header.opcode == MAGNUS_WS_OPCODE_CONTINUATION);
    assert(!header.fin);

    return 0;
}
