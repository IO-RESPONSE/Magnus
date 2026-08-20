#include "magnus_ws.h"

#include <string.h>

magnus_ws_header_result_t
magnus_ws_parse_header(const unsigned char *data, size_t length,
                       magnus_ws_frame_header_t *out)
{
    unsigned char byte0, byte1;
    size_t offset;
    size_t extended_length_bytes;
    uint64_t payload_length;

    memset(out, 0, sizeof(*out));
    if (length < 2) return MAGNUS_WS_HEADER_INCOMPLETE;

    byte0 = data[0];
    byte1 = data[1];

    /* RSV1-3 must be 0: this codebase negotiates no extensions (no
     * permessage-deflate, nothing), so a set reserved bit can only mean
     * a peer assuming an extension that was never agreed to. */
    if ((byte0 & 0x70) != 0) return MAGNUS_WS_HEADER_INVALID;

    out->fin = (byte0 & 0x80) != 0;
    out->opcode = byte0 & 0x0F;
    if (!(out->opcode <= MAGNUS_WS_OPCODE_BINARY
          || (out->opcode >= MAGNUS_WS_OPCODE_CLOSE
              && out->opcode <= MAGNUS_WS_OPCODE_PONG)))
        return MAGNUS_WS_HEADER_INVALID;

    out->masked = (byte1 & 0x80) != 0;
    {
        unsigned char length7 = byte1 & 0x7F;
        if (length7 <= 125) {
            payload_length = length7;
            extended_length_bytes = 0;
        } else if (length7 == 126) {
            extended_length_bytes = 2;
            payload_length = 0; /* filled in below once the bytes are known present */
        } else {
            extended_length_bytes = 8;
            payload_length = 0;
        }
    }

    offset = 2;
    if (length < offset + extended_length_bytes) return MAGNUS_WS_HEADER_INCOMPLETE;
    if (extended_length_bytes == 2) {
        payload_length = ((uint64_t) data[offset] << 8) | (uint64_t) data[offset + 1];
        /* RFC 6455 5.2: the minimal encoding must be used -- a 16-bit
         * length that could have fit in the 7-bit field is a violation,
         * not a merely inefficient-but-valid frame. */
        if (payload_length <= 125) return MAGNUS_WS_HEADER_INVALID;
        offset += 2;
    } else if (extended_length_bytes == 8) {
        payload_length = 0;
        for (size_t i = 0; i < 8; i++)
            payload_length = (payload_length << 8) | (uint64_t) data[offset + i];
        if (payload_length <= UINT64_C(0xFFFF)) return MAGNUS_WS_HEADER_INVALID;
        if ((payload_length & (UINT64_C(1) << 63)) != 0)
            return MAGNUS_WS_HEADER_INVALID;
        offset += 8;
    }

    /* Control frames may never be fragmented and are capped at 125 bytes
     * of payload -- section 5.5. */
    if (out->opcode >= MAGNUS_WS_OPCODE_CLOSE
        && (!out->fin || payload_length > 125))
        return MAGNUS_WS_HEADER_INVALID;

    if (out->masked) {
        if (length < offset + 4) return MAGNUS_WS_HEADER_INCOMPLETE;
        memcpy(out->mask_key, data + offset, 4);
        offset += 4;
    }

    out->payload_length = payload_length;
    out->header_length = offset;
    return MAGNUS_WS_HEADER_OK;
}

bool
magnus_ws_mask_direction_ok(const magnus_ws_frame_header_t *header,
                            bool from_client)
{
    return header->masked == from_client;
}
