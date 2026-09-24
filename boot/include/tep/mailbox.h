/*
 * NXU <-> tepOS mailbox protocol, version 1.
 *
 * The external interface of the Trusted Enclave Processor. It runs over a
 * byte stream (a dedicated serial link between the two machines); nothing
 * else connects NXU to tepOS, and no command reads or writes memory.
 * NXU keeps a copy of these definitions (nxu: drivers/tep/tep_mailbox_proto.h);
 * the two must match, which HELLO checks at run time through the version.
 *
 * Frame, all fields little endian:
 *
 *   off  size  field
 *     0     2  magic          TEP_MB_MAGIC ("TP")
 *     2     1  version        TEP_MB_VERSION
 *     3     1  type           TEP_MB_TYPE_REQUEST / TEP_MB_TYPE_RESPONSE
 *     4     2  command        enum tep_mb_command
 *     6     2  status         enum tep_mb_status (0 in requests)
 *     8     4  request_id     chosen by NXU, echoed in the response
 *    12     2  payload_len    <= TEP_MB_MAX_PAYLOAD, exact per command
 *    14     2  reserved       0
 *    16     n  payload
 *  16+n     4  crc32          IEEE 802.3 CRC-32 over bytes 0 .. 16+n-1
 *
 * The CRC only detects corruption on the link; it is not authentication.
 * A receiver that sees a bad magic, bad length or bad CRC discards bytes
 * until the next magic; NXU times out and retries. Requests with a bad
 * version, unknown command or wrong payload length get a response with the
 * matching status and an empty payload. One request is outstanding at a time.
 */

#pragma once

#define TEP_MB_MAGIC        0x5054u     /* bytes 'T' 'P' */
#define TEP_MB_VERSION      1u
#define TEP_MB_HEADER_LEN   16u
#define TEP_MB_CRC_LEN      4u
#define TEP_MB_MAX_PAYLOAD  240u
#define TEP_MB_MAX_FRAME    (TEP_MB_HEADER_LEN + TEP_MB_MAX_PAYLOAD + TEP_MB_CRC_LEN)

#define TEP_MB_TYPE_REQUEST  1u
#define TEP_MB_TYPE_RESPONSE 2u

enum tep_mb_command {
    TEP_MB_CMD_HELLO      = 0x0001,     /* request: empty; response: tep_mb_hello */
    TEP_MB_CMD_GET_HEALTH = 0x0002,     /* request: empty; response: tep_mb_health */

    /* TEP_MB_FEATURE_CRYPTO: */
    TEP_MB_CMD_SHA256       = 0x0010,   /* request: 1..240 bytes; response: 32-byte digest */
    TEP_MB_CMD_RANDOM       = 0x0011,   /* request: u16 n (1..64); response: n random bytes */
    TEP_MB_CMD_KEY_GENERATE = 0x0020,   /* request: u8 algorithm; response: u32 handle */
    TEP_MB_CMD_KEY_PUBLIC   = 0x0021,   /* request: u32 handle; response: 32-byte public key */
    TEP_MB_CMD_KEY_SIGN     = 0x0022,   /* request: u32 handle, 1..224 bytes; response: 64-byte signature */
    TEP_MB_CMD_KEY_DELETE   = 0x0023,   /* request: u32 handle; response: empty */
};

/*
 * Keys are generated inside tepOS and named by an opaque u32 handle; private
 * keys never cross the mailbox. Algorithms: TEP_MB_ALG_ED25519 (RFC 8032).
 * Signatures cover the message bytes as sent.
 */
#define TEP_MB_ALG_ED25519 1u
#define TEP_MB_SHA256_MAX 240u
#define TEP_MB_RANDOM_MAX 64u
#define TEP_MB_SIGN_MAX   224u

enum tep_mb_status {
    TEP_MB_OK            = 0,
    TEP_MB_BAD_VERSION   = 1,
    TEP_MB_BAD_COMMAND   = 2,
    TEP_MB_BAD_LENGTH    = 3,
    TEP_MB_UNAVAILABLE   = 4,   /* tepOS cannot serve this right now */
    TEP_MB_INTERNAL      = 5,
    TEP_MB_NOT_FOUND     = 6,   /* no such key handle (for this caller) */
    TEP_MB_FULL          = 7,   /* no room for another key */
};

/*
 * HELLO response payload, 12 bytes:
 *   0  u16 protocol version (TEP_MB_VERSION)
 *   2  u16 flags: TEP_MB_FEATURE_* the tepOS answering supports
 *   4  u32 tepOS version, major << 16 | minor << 8 | patch
 *   8  u32 boot id: changes when tepOS reboots (not secret, not random)
 */
#define TEP_MB_HELLO_LEN 12u
#define TEP_MB_FEATURE_CRYPTO (1u << 0)    /* SHA256, RANDOM and the KEY_* commands */

/*
 * GET_HEALTH response payload, 4 + 4 * n bytes:
 *   0  u8  health (enum tep_mb_health)
 *   1  u8  n, number of services (<= TEP_MB_MAX_SERVICES)
 *   2  u16 reserved (0)
 *   then n entries of: u8 service id, u8 state (enum tep_mb_service_state),
 *                      u8 restarts, u8 reserved (0)
 */
#define TEP_MB_MAX_SERVICES 8u
#define TEP_MB_HEALTH_LEN(n) (4u + 4u * (n))

enum tep_mb_health {
    TEP_MB_HEALTH_STARTING = 0,
    TEP_MB_HEALTH_OK       = 1,
    TEP_MB_HEALTH_DEGRADED = 2,
    TEP_MB_HEALTH_FAILED   = 3,
};

enum tep_mb_service_state {
    TEP_MB_SVC_STOPPED  = 0,
    TEP_MB_SVC_STARTING = 1,
    TEP_MB_SVC_READY    = 2,
    TEP_MB_SVC_FAILED   = 3,
    TEP_MB_SVC_DISABLED = 4,
};
