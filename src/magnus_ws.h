#ifndef MAGNUS_WS_H
#define MAGNUS_WS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RFC 6455 frame-header parsing, kept deliberately separate from (and not
 * wired into) the actual proxy relay path: once a WebSocket upgrade
 * handshake completes, magnus.c relays the connection as a raw
 * bidirectional byte pipe -- correctness and memory safety there come
 * from the same bounded-chunk streaming already used for ordinary
 * proxied response bodies, regardless of what the bytes mean at the
 * WebSocket framing layer, so full per-frame reassembly is not needed
 * for the relay to work or be safe. This module exists because a new
 * binary parser is new attack surface and gets fuzzed
 * (tests/fuzz-ws.c) like every other one in this codebase, and because
 * frame-header-level validation (masking direction, minimal-length-
 * encoding, reserved bits, control-frame constraints) is real,
 * independently useful groundwork for wiring in live per-frame policy
 * later -- see docs/development-roadmap.md's 1d entry. */

typedef enum {
    MAGNUS_WS_OPCODE_CONTINUATION = 0x0,
    MAGNUS_WS_OPCODE_TEXT = 0x1,
    MAGNUS_WS_OPCODE_BINARY = 0x2,
    MAGNUS_WS_OPCODE_CLOSE = 0x8,
    MAGNUS_WS_OPCODE_PING = 0x9,
    MAGNUS_WS_OPCODE_PONG = 0xA
} magnus_ws_opcode_t;

typedef struct {
    bool fin;
    unsigned opcode;
    bool masked;
    uint8_t mask_key[4]; /* valid only when masked is true */
    uint64_t payload_length;
    /* Total bytes this header occupied (2 base + 0/2/8 extended-length +
     * 0/4 mask key) -- where the payload starts in whatever buffer the
     * header was parsed from. */
    size_t header_length;
} magnus_ws_frame_header_t;

typedef enum {
    /* A complete, well-formed header was found; `out` is filled in. */
    MAGNUS_WS_HEADER_OK,
    /* Not wrong yet, just not all here -- ask again once more bytes have
     * arrived. Never returned once MAGNUS_WS_HEADER_INVALID would apply
     * to the bytes seen so far. */
    MAGNUS_WS_HEADER_INCOMPLETE,
    /* The bytes present already violate RFC 6455's frame format: a
     * reserved bit set (no extension is negotiated, so none may be),
     * an opcode outside the defined set, a length not encoded in its
     * required minimal form, the 64-bit length's high bit set, or a
     * control frame (opcode >= 0x8) that is fragmented or has a payload
     * over 125 bytes -- ee section 5.2/5.5. */
    MAGNUS_WS_HEADER_INVALID
} magnus_ws_header_result_t;

/* Parses a WebSocket frame header from the first `length` bytes of
 * `data`, never reading past `length`. `out` is unspecified except on
 * MAGNUS_WS_HEADER_OK. */
magnus_ws_header_result_t magnus_ws_parse_header(const unsigned char *data,
                                                  size_t length,
                                                  magnus_ws_frame_header_t *out);

/* True if `header`'s mask bit matches what RFC 6455 requires for a frame
 * traveling in the given direction: masked when `from_client` is true,
 * unmasked when it is false. A reverse proxy that is not itself an
 * endpoint has no reason to unmask/remask payload data -- this exists to
 * let a caller reject a frame whose masking is already wrong for its
 * direction as a protocol violation, without needing to touch the
 * payload at all. */
bool magnus_ws_mask_direction_ok(const magnus_ws_frame_header_t *header,
                                 bool from_client);

#endif
