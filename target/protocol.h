#ifndef BROKER_PROTOCOL_H
#define BROKER_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define BROKER_MAGIC UINT32_C(0x42524b52) /* BRKR */
#define BROKER_VERSION 1u
#define BROKER_MAX_PAYLOAD 4096u
#define BROKER_FLAG_RESPONSE UINT16_C(0x8000)

enum broker_opcode {
    BROKER_OP_HELLO      = 0x01,
    BROKER_OP_AUTH_BEGIN = 0x02,
    BROKER_OP_AUTH_ABORT = 0x03,
    BROKER_OP_AUTH_FINISH = 0x04,
    BROKER_OP_QUEUE      = 0x10,
    BROKER_OP_CANCEL     = 0x11,
    BROKER_OP_INSPECT    = 0x12,
    BROKER_OP_NOTE       = 0x13,
    BROKER_OP_DISPATCH   = 0x14,
    BROKER_OP_QUIT       = 0x7f,
};

enum broker_phase {
    BROKER_PHASE_NEW           = 0,
    BROKER_PHASE_READY         = 1,
    BROKER_PHASE_AUTHENTICATED = 2,
    BROKER_PHASE_AUTH_PENDING  = 3,
};

enum broker_status {
    BROKER_STATUS_OK          = 0,
    BROKER_STATUS_BAD_MAGIC   = 1,
    BROKER_STATUS_BAD_VERSION = 2,
    BROKER_STATUS_BAD_FLAGS   = 3,
    BROKER_STATUS_TOO_LARGE   = 4,
    BROKER_STATUS_BAD_OPCODE  = 5,
    BROKER_STATUS_BAD_STATE   = 6,
    BROKER_STATUS_BAD_PAYLOAD = 7,
    BROKER_STATUS_NOT_FOUND   = 8,
    BROKER_STATUS_DENIED      = 9,
    BROKER_STATUS_BUSY        = 10,
    BROKER_STATUS_NOMEM       = 11,
    BROKER_STATUS_IO          = 12,
};

/* All multibyte fields are big-endian on the wire. */
struct broker_frame_header {
    uint32_t magic;
    uint8_t version;
    uint8_t opcode;
    uint16_t flags;
    uint32_t request_id;
    uint32_t payload_len;
};

_Static_assert(sizeof(struct broker_frame_header) == 16, "wire header size");
_Static_assert(offsetof(struct broker_frame_header, version) == 4, "version offset");
_Static_assert(offsetof(struct broker_frame_header, flags) == 6, "flags offset");
_Static_assert(offsetof(struct broker_frame_header, request_id) == 8, "request id offset");
_Static_assert(offsetof(struct broker_frame_header, payload_len) == 12, "payload length offset");

#endif
