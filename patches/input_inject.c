/* Phone-originated input injection: the one direction stock firmware has no
 * route for. Wire format on sid 0xf0:
 *
 *     [32][dev u8][event_id u32 LE][diffx u8][speed u8]        8 bytes
 *
 * Rebuilt into the stock 12-byte input record (+0 u16 dev_type, +4 u32
 * event_id, +8 u8 diffx, +9 u8 speed) and handed to stock SendDataToBoth with
 * type 0x108 - byte-identical to what the ring-touch driver does.
 *
 * SendDataToBoth dispatches on BOTH lenses, not just the peer: the peer runs it
 * on frame arrival (listener_common1 -> user_response -> UI registry row 23),
 * and the CALLING lens runs the same payload through its own TinyFrame
 * send-listener once the peer ACKs with 0x0a (send_begin_type1.c:63-75, whose
 * bl resolves to 0x00465f10 - the function Faceclaw already hooks as
 * CFW_STOCK_BRIDGE_RECEIVE). So the comment in message_transport.c:9 about a
 * local echo is right, and SPEC-input-injection.md section 8.1 was wrong to call
 * this peer-directed.
 *
 * The record is still addressed to the LEFT lens, for better reasons than the
 * spec gave: LEFT reaches the master in one hop and does not depend on a peer
 * ACK. RIGHT would also work, one UART round trip later. BOTH would make the
 * master dispatch TWICE and double-advance the UI, so the side guard below
 * turns a mis-addressed record into a visible NACK instead of a double scroll.
 *
 * Values are whitelisted, not passed through: PRESS/RELEASE (13/14) on the
 * temple bars latch inpm_both_long_press_active(), which rejects ALL input -
 * including the physical bars - until released, and toggles silent mode, a
 * persisted setting. 0x1010 goes to a different path entirely.
 *
 * Rate limited because the master's handler tails into SendInputEventToPeers,
 * whose queue-full path masks interrupts, faults deliberately and spins. Stock
 * never reaches it because events come from a finger; a phone over BLE would.
 *
 * Deliberately NOT gated on cfw_fb_lease_active(): gesture_fwd.c:157 takes that
 * lease because it is driving Faceclaw's framebuffer. We are driving the STOCK
 * UI, so the lease must not be required and must not be taken.
 */
#include <stdint.h>
#include "cfw_context.h"

#define INPM_EVENT_MSG_ID      0x108u
#define INJECT_MIN_INTERVAL_MS 20u

/* The fourth argument is a completion CALLBACK, not an opaque word: stock stores
 * it to node->id (display_input_event_send.c:44), carries it into the TinyFrame
 * record as f.id (process_event2.c:72) and then CALLS it as void(*)(uint32_t) on
 * ACK (send_begin_type1.c:78-86) and with status -2 on timeout
 * (send_timeout_end.c:46-58). Passing 0 is mandatory, not stylistic - any
 * non-zero non-pointer value there is branched to. */
typedef int32_t (*send_both_fn)(uint16_t type, const void *payload,
                                uint32_t length, void *done_cb);
#define FW_SEND_DATA_TO_BOTH ((send_both_fn)0x0046a861u)

int cfw_inject_input(const uint8_t *src, uint32_t srclen)
{
    if (src == 0 || srclen < 8u) return -1;

    /* Only the left lens injects. Mirrors gesture_fwd.c:163. Without this, a
     * record addressed to BOTH lenses reaches the master twice. */
    if (FW_SIDE_ID() != 2u) return -1;

    uint32_t dev   = src[1];
    uint32_t event = (uint32_t)src[2]
                   | ((uint32_t)src[3] << 8)
                   | ((uint32_t)src[4] << 16)
                   | ((uint32_t)src[5] << 24);

    if (dev != 0u && dev != 1u && dev != 4u) return -1;
    if (event == 2u || event > 5u) return -1;      /* {0,1,3,4,5} only */

    customCfwContext *ctx = faceclaw_context_if_valid();
    if (ctx == 0) return -1;

    uint32_t now = FW_MS_TICK;
    if (ctx->inject_last_tick != 0u &&
        (uint32_t)(now - ctx->inject_last_tick) < INJECT_MIN_INTERVAL_MS)
        return -1;
    ctx->inject_last_tick = (now == 0u) ? 1u : now;

    uint32_t ev[3];
    ev[0] = dev;                                   /* +0 u16 dev_type, +2 pad */
    ev[1] = event;                                 /* +4 u32 event_id */
    ev[2] = (uint32_t)src[6] | ((uint32_t)src[7] << 8);  /* +8 diffx, +9 speed */

    /* The 12 is a safety invariant, not a formality: the receiving handler does
     * memcpy(&event, data, length) into 12 bytes of stack with length taken
     * straight off the wire and NOT bounded by the record size
     * (service_input_manager.c:288-295). Any path that lets a caller-supplied
     * length reach here smashes the master's stack. */
    (void)FW_SEND_DATA_TO_BOTH((uint16_t)INPM_EVENT_MSG_ID, ev, 12u, 0);
    return 0;
}
