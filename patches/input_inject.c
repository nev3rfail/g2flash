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
 * local echo is right. SPEC-input-injection.md section 8.1 said the opposite in
 * v3 and was corrected in v4; it now agrees with this comment, so a reader
 * following the citation should find agreement, not a dispute.
 *
 * The record is still addressed to the LEFT lens, for better reasons than the
 * spec gave: LEFT reaches the master in one hop and does not depend on a peer
 * ACK. RIGHT would also work, one UART round trip later. BOTH would make the
 * master dispatch TWICE and double-advance the UI, so the side guard below
 * drops the copy that lands on the right lens. The guard is silent: it ACKs
 * like every other path here (see the block above cfw_inject_input), so a
 * mis-addressed record is invisible on the wire and is caught only by watching
 * the display.
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
 * Deliberately NOT gated on cfw_fb_lease_active(): gesture_fwd.c:155-157 takes that
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

/* EVERY return from this function is 0, including every refusal, and that is
 * load-bearing rather than sloppy.
 *
 * The private transport has no benign "rejected" signal. Any non-zero return
 * from the dispatch chain reaches cfw_message_complete, which does
 * `cfw_inflate_reset(stream); stream->context_valid = 0;` with the comment
 * "only an explicit record reset can recover" (message_transport.c). The flag
 * is sticky and per ingress lens, so one NACK kills the whole sid-0xf0 stream
 * for that lens - injection records and Faceclaw image traffic alike - until a
 * record carrying CFW_MESSAGE_RESET_CONTEXT arrives. A NACK is therefore not a
 * cheap "no"; it is a transport kill.
 *
 * Refusal here is a DESIGNED, ROUTINE outcome: the 20 ms rate limit exists
 * precisely so that over-rate injections are dropped, and a phone holding a
 * d-pad down will hit it constantly. Handing a routine drop the power to take
 * the transport down trades a bounded, invisible miss for an unbounded, total
 * one. So mode 32 ACKs whatever it does with the record.
 *
 * The cost, stated plainly: for mode 32 an ACK means RECEIVED, not INJECTED.
 * That suspends this project's "judge a send by its ack" rule for this one
 * message. The phone must pace itself above the 20 ms floor and judge an
 * injection by watching the display, never by the reply code. Written into
 * SPEC-input-injection.md sections 4.4, 5.3 and 8 so it is not rediscovered.
 */
int cfw_inject_input(const uint8_t *src, uint32_t srclen)
{
    if (src == 0 || srclen < 8u) return 0;

    /* Only the left lens injects. Mirrors gesture_fwd.c:163-164. Without this,
     * a record addressed to BOTH lenses reaches the master twice. */
    if (FW_SIDE_ID() != 2u) return 0;

    uint32_t dev   = src[1];
    uint32_t event = (uint32_t)src[2]
                   | ((uint32_t)src[3] << 8)
                   | ((uint32_t)src[4] << 16)
                   | ((uint32_t)src[5] << 24);

    if (dev != 0u && dev != 1u && dev != 4u) return 0;
    if (event == 2u || event > 5u) return 0;      /* {0,1,3,4,5} only */

    customCfwContext *ctx = faceclaw_context_if_valid();
    if (ctx == 0) return 0;

    /* THE FLOOR IS NOT HARD, and the next person must not assume it is. This
     * read-compare-write is not atomic, and since the mode-32 dispatch moved
     * out of image_mutex (zlib_glue.c, finding C1) nothing serialises it. The
     * two ingress paths are separate tasks - BLE receive via
     * cfw_receive_packet and inter-arm bridge receive via
     * cfw_message_bridge_received, both landing in cfw_message_process with
     * their own streams - so a phone writing to both arms at once can have two
     * records read the same old tick, both pass this test and both send. The
     * excess is bounded at exactly 2x (one per ingress path), i.e. an
     * effective 10 ms floor, not unbounded. Accepted deliberately: 10 ms is
     * still far slower than the queue the floor guards, and the phone is
     * required to pace itself anyway (spec section 6.2). If it ever needs to
     * be hard, make it an __atomic_compare_exchange_n on inject_last_tick -
     * zlib_glue.c's image_mutex creation already shows the idiom in this
     * tree. Recorded in SPEC-input-injection.md section 5.3. */
    uint32_t now = FW_MS_TICK;
    if (ctx->inject_last_tick != 0u &&
        (uint32_t)(now - ctx->inject_last_tick) < INJECT_MIN_INTERVAL_MS)
        return 0;
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
    /* The return value is DELIBERATELY discarded, and the discard is not free.
     * Stock SendDataToBoth returns -1 on a null queue pointer, on either
     * CommonMalloc giving up after ten retries, and on audio_cmsis_queue_put
     * failing after its 2000 ms wait (display_input_event_send.c) - on each of
     * those the event never leaves this lens. Propagating that into a NACK is
     * what the obvious reading asks for, and it is exactly what the comment
     * above this function forbids: it would hand a transient, routine send
     * failure the power to zero context_valid and kill the sid-0xf0 stream for
     * this lens until a RESET_CONTEXT record arrives. A dropped event is
     * recoverable by sending another; a dead transport is not.
     *
     * What the discard costs: a failed send ACKs like a successful one, so the
     * phone's model of the stock UI can silently drift from what the lenses
     * show. The rate limiter has also already been advanced above, so the
     * window is consumed either way. The mitigation is not in the firmware -
     * it is the operator watching the display, which is what every acceptance
     * criterion in the spec is written to require. */
    (void)FW_SEND_DATA_TO_BOTH((uint16_t)INPM_EVENT_MSG_ID, ev, 12u, 0);
    return 0;
}
