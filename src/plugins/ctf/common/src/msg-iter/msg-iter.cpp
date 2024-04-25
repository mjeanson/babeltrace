/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2015-2018 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015-2018 Philippe Proulx <pproulx@efficios.com>
 *
 * Babeltrace - CTF message iterator
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "common/assert.h"
#include "common/common.h"
#include "cpp-common/bt2c/fmt.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2c/make-span.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "../bfcr/bfcr.hpp"
#include "msg-iter.hpp"

/* A visit stack entry */
struct stack_entry
{
    /*
     * Current base field, one of:
     *
     *   * string
     *   * structure
     *   * array
     *   * sequence
     *   * variant
     *
     * Field is borrowed.
     */
    bt_field *base;

    /* Index of next field to set */
    size_t index;
};

/* Visit stack */
struct stack
{
    struct ctf_msg_iter *msg_it;

    /* Entries (struct stack_entry) */
    GArray *entries;

    /* Number of active entries */
    size_t size;
};

/* State */
enum state
{
    STATE_INIT,
    STATE_SWITCH_PACKET,
    STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN,
    STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE,
    STATE_AFTER_TRACE_PACKET_HEADER,
    STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN,
    STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE,
    STATE_AFTER_STREAM_PACKET_CONTEXT,
    STATE_EMIT_MSG_STREAM_BEGINNING,
    STATE_CHECK_EMIT_MSG_DISCARDED_EVENTS,
    STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS,
    STATE_EMIT_MSG_DISCARDED_EVENTS,
    STATE_EMIT_MSG_DISCARDED_PACKETS,
    STATE_EMIT_MSG_PACKET_BEGINNING,
    STATE_DSCOPE_EVENT_HEADER_BEGIN,
    STATE_DSCOPE_EVENT_HEADER_CONTINUE,
    STATE_AFTER_EVENT_HEADER,
    STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN,
    STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE,
    STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN,
    STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE,
    STATE_DSCOPE_EVENT_PAYLOAD_BEGIN,
    STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE,
    STATE_EMIT_MSG_EVENT,
    STATE_EMIT_QUEUED_MSG_EVENT,
    STATE_SKIP_PACKET_PADDING,
    STATE_EMIT_MSG_PACKET_END_MULTI,
    STATE_EMIT_MSG_PACKET_END_SINGLE,
    STATE_EMIT_QUEUED_MSG_PACKET_END,
    STATE_CHECK_EMIT_MSG_STREAM_END,
    STATE_EMIT_MSG_STREAM_END,
    STATE_DONE,
};

static __attribute__((used)) const char *format_as(state state)
{
    switch (state) {
    case STATE_INIT:
        return "STATE_INIT";

    case STATE_SWITCH_PACKET:
        return "STATE_SWITCH_PACKET";

    case STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN:
        return "STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN";

    case STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE:
        return "STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE";

    case STATE_AFTER_TRACE_PACKET_HEADER:
        return "STATE_AFTER_TRACE_PACKET_HEADER";

    case STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN:
        return "STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN";

    case STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE:
        return "STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE";

    case STATE_AFTER_STREAM_PACKET_CONTEXT:
        return "STATE_AFTER_STREAM_PACKET_CONTEXT";

    case STATE_EMIT_MSG_STREAM_BEGINNING:
        return "STATE_EMIT_MSG_STREAM_BEGINNING";

    case STATE_CHECK_EMIT_MSG_DISCARDED_EVENTS:
        return "STATE_CHECK_EMIT_MSG_DISCARDED_EVENTS";

    case STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS:
        return "STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS";

    case STATE_EMIT_MSG_DISCARDED_EVENTS:
        return "STATE_EMIT_MSG_DISCARDED_EVENTS";

    case STATE_EMIT_MSG_DISCARDED_PACKETS:
        return "STATE_EMIT_MSG_DISCARDED_PACKETS";

    case STATE_EMIT_MSG_PACKET_BEGINNING:
        return "STATE_EMIT_MSG_PACKET_BEGINNING";

    case STATE_DSCOPE_EVENT_HEADER_BEGIN:
        return "STATE_DSCOPE_EVENT_HEADER_BEGIN";

    case STATE_DSCOPE_EVENT_HEADER_CONTINUE:
        return "STATE_DSCOPE_EVENT_HEADER_CONTINUE";

    case STATE_AFTER_EVENT_HEADER:
        return "STATE_AFTER_EVENT_HEADER";

    case STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN:
        return "STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN";

    case STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE:
        return "STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE";

    case STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN:
        return "STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN";

    case STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE:
        return "STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE";

    case STATE_DSCOPE_EVENT_PAYLOAD_BEGIN:
        return "STATE_DSCOPE_EVENT_PAYLOAD_BEGIN";

    case STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE:
        return "STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE";

    case STATE_EMIT_MSG_EVENT:
        return "STATE_EMIT_MSG_EVENT";

    case STATE_EMIT_QUEUED_MSG_EVENT:
        return "STATE_EMIT_QUEUED_MSG_EVENT";

    case STATE_SKIP_PACKET_PADDING:
        return "STATE_SKIP_PACKET_PADDING";

    case STATE_EMIT_MSG_PACKET_END_MULTI:
        return "STATE_EMIT_MSG_PACKET_END_MULTI";

    case STATE_EMIT_MSG_PACKET_END_SINGLE:
        return "STATE_EMIT_MSG_PACKET_END_SINGLE";

    case STATE_EMIT_QUEUED_MSG_PACKET_END:
        return "STATE_EMIT_QUEUED_MSG_PACKET_END";

    case STATE_CHECK_EMIT_MSG_STREAM_END:
        return "STATE_CHECK_EMIT_MSG_STREAM_END";

    case STATE_EMIT_MSG_STREAM_END:
        return "STATE_EMIT_MSG_STREAM_END";

    case STATE_DONE:
        return "STATE_DONE";
    }

    bt_common_abort();
}

struct end_of_packet_snapshots
{
    uint64_t discarded_events = 0;
    uint64_t packets = 0;
    uint64_t beginning_clock = 0;
    uint64_t end_clock = 0;
};

/* CTF message iterator */
struct ctf_msg_iter
{
    explicit ctf_msg_iter(bt2c::Logger loggerParam) noexcept : logger {std::move(loggerParam)}
    {
    }

    /* Visit stack */
    struct stack *stack = nullptr;

    /* Current message iterator to create messages (weak) */
    bt_self_message_iterator *self_msg_iter = nullptr;

    /*
     * True if library objects are unavailable during the decoding and
     * should not be created/used.
     */
    bool dry_run = false;

    /*
     * Current dynamic scope field pointer.
     *
     * This is set by read_dscope_begin_state() and contains the
     * value of one of the pointers in `dscopes` below.
     */
    bt_field *cur_dscope_field = nullptr;

    /*
     * True if we're done filling a string field from a text
     * array/sequence payload.
     */
    bool done_filling_string = false;

    /* Trace and classes */
    /* True to set IR fields */
    bool set_ir_fields = false;

    struct
    {
        struct ctf_trace_class *tc = nullptr;
        struct ctf_stream_class *sc = nullptr;
        struct ctf_event_class *ec = nullptr;
    } meta;

    /* Current packet (NULL if not created yet) */
    bt_packet *packet = nullptr;

    /* Current stream (NULL if not set yet) */
    bt_stream *stream = nullptr;

    /* Current event (NULL if not created yet) */
    bt_event *event = nullptr;

    /* Current event message (NULL if not created yet) */
    bt_message *event_msg = nullptr;

    /*
     * True if we need to emit a packet beginning message before we emit
     * the next event message or the packet end message.
     */
    bool emit_delayed_packet_beginning_msg = false;

    /*
     * True if this is the first packet we are reading, and therefore if we
     * should emit a stream beginning message.
     */
    bool emit_stream_beginning_message = false;

    /*
     * True if we need to emit a stream end message at the end of the
     * current stream. A live stream may never receive any data and thus
     * never send a stream beginning message which removes the need to emit
     * a stream end message.
     */
    bool emit_stream_end_message = false;

    /* Database of current dynamic scopes */
    struct
    {
        bt_field *stream_packet_context = nullptr;
        bt_field *event_common_context = nullptr;
        bt_field *event_spec_context = nullptr;
        bt_field *event_payload = nullptr;
    } dscopes;

    /* Current state */
    enum state state = STATE_INIT;

    /* Current medium buffer data */
    struct
    {
        /* Last address provided by medium */
        const uint8_t *addr = nullptr;

        /* Buffer size provided by medium (bytes) */
        size_t sz = 0;

        /* Offset within whole packet of addr (bits) */
        size_t packet_offset = 0;

        /* Current position from addr (bits) */
        size_t at = 0;

        /* Position of the last event header from addr (bits) */
        size_t last_eh_at = 0;
    } buf;

    /* Binary type reader */
    struct bt_bfcr *bfcr = nullptr;

    /* Current medium data */
    struct
    {
        struct ctf_msg_iter_medium_ops medops;
        size_t max_request_sz = 0;
        void *data = nullptr;
    } medium;

    /* Current packet size (bits) (-1 if unknown) */
    int64_t cur_exp_packet_total_size = 0;

    /* Current content size (bits) (-1 if unknown) */
    int64_t cur_exp_packet_content_size = 0;

    /* Current stream class ID */
    int64_t cur_stream_class_id = 0;

    /* Current event class ID */
    int64_t cur_event_class_id = 0;

    /* Current data stream ID */
    int64_t cur_data_stream_id = 0;

    /*
     * Offset, in the underlying media, of the current packet's
     * start (-1 if unknown).
     */
    off_t cur_packet_offset = 0;

    /* Default clock's current value */
    uint64_t default_clock_snapshot = 0;

    /* End of current packet snapshots */
    struct end_of_packet_snapshots snapshots;

    /* End of previous packet snapshots */
    struct end_of_packet_snapshots prev_packet_snapshots;

    /* Stored values (for sequence lengths, variant tags) */
    GArray *stored_values = nullptr;

    bt2c::Logger logger;
};

static struct stack *stack_new(struct ctf_msg_iter *msg_it)
{
    struct stack *stack = NULL;

    stack = g_new0(struct stack, 1);
    if (!stack) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger, "Failed to allocate one stack.");
        goto error;
    }

    stack->msg_it = msg_it;
    stack->entries = g_array_new(FALSE, TRUE, sizeof(struct stack_entry));
    if (!stack->entries) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger, "Failed to allocate a GArray.");
        goto error;
    }

    BT_CPPLOGD_SPEC(msg_it->logger, "Created stack: msg-it-addr={}, stack-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(stack));
    goto end;

error:
    g_free(stack);
    stack = NULL;

end:
    return stack;
}

static void stack_destroy(struct stack *stack)
{
    struct ctf_msg_iter *msg_it;

    BT_ASSERT_DBG(stack);
    msg_it = stack->msg_it;
    BT_CPPLOGD_SPEC(msg_it->logger, "Destroying stack: addr={}", fmt::ptr(stack));

    if (stack->entries) {
        g_array_free(stack->entries, TRUE);
    }

    g_free(stack);
}

static void stack_push(struct stack *stack, bt_field *base)
{
    struct stack_entry *entry;
    struct ctf_msg_iter *msg_it;

    BT_ASSERT_DBG(stack);
    msg_it = stack->msg_it;
    BT_ASSERT_DBG(base);
    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Pushing base field on stack: stack-addr={}, "
                    "stack-size-before={}, stack-size-after={}",
                    fmt::ptr(stack), stack->size, stack->size + 1);

    if (stack->entries->len == stack->size) {
        g_array_set_size(stack->entries, stack->size + 1);
    }

    entry = &bt_g_array_index(stack->entries, struct stack_entry, stack->size);
    entry->base = base;
    entry->index = 0;
    stack->size++;
}

static inline unsigned int stack_size(struct stack *stack)
{
    BT_ASSERT_DBG(stack);
    return stack->size;
}

static void stack_pop(struct stack *stack)
{
    struct ctf_msg_iter *msg_it;

    BT_ASSERT_DBG(stack);
    BT_ASSERT_DBG(stack_size(stack));
    msg_it = stack->msg_it;
    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Popping from stack: "
                    "stack-addr={}, stack-size-before={}, stack-size-after={}",
                    fmt::ptr(stack), stack->size, stack->size - 1);
    stack->size--;
}

static inline struct stack_entry *stack_top(struct stack *stack)
{
    BT_ASSERT_DBG(stack);
    BT_ASSERT_DBG(stack_size(stack));
    return &bt_g_array_index(stack->entries, struct stack_entry, stack->size - 1);
}

static inline bool stack_empty(struct stack *stack)
{
    return stack_size(stack) == 0;
}

static void stack_clear(struct stack *stack)
{
    BT_ASSERT_DBG(stack);
    stack->size = 0;
}

static inline enum ctf_msg_iter_status
msg_iter_status_from_m_status(enum ctf_msg_iter_medium_status m_status)
{
    /* They are the same */
    return (ctf_msg_iter_status) m_status;
}

static inline size_t buf_size_bits(struct ctf_msg_iter *msg_it)
{
    return msg_it->buf.sz * 8;
}

static inline size_t buf_available_bits(struct ctf_msg_iter *msg_it)
{
    return buf_size_bits(msg_it) - msg_it->buf.at;
}

static inline size_t packet_at(struct ctf_msg_iter *msg_it)
{
    return msg_it->buf.packet_offset + msg_it->buf.at;
}

static inline void buf_consume_bits(struct ctf_msg_iter *msg_it, size_t incr)
{
    BT_CPPLOGT_SPEC(msg_it->logger, "Advancing cursor: msg-it-addr={}, cur-before={}, cur-after={}",
                    fmt::ptr(msg_it), msg_it->buf.at, msg_it->buf.at + incr);
    msg_it->buf.at += incr;
}

static enum ctf_msg_iter_status request_medium_bytes(struct ctf_msg_iter *msg_it)
{
    uint8_t *buffer_addr = NULL;
    size_t buffer_sz = 0;
    enum ctf_msg_iter_medium_status m_status;

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Calling user function (request bytes): msg-it-addr={}, "
                    "request-size={}",
                    fmt::ptr(msg_it), msg_it->medium.max_request_sz);
    m_status = msg_it->medium.medops.request_bytes(msg_it->medium.max_request_sz, &buffer_addr,
                                                   &buffer_sz, msg_it->medium.data);
    BT_CPPLOGD_SPEC(msg_it->logger, "User function returned: status={}, buf-addr={}, buf-size={}",
                    m_status, fmt::ptr(buffer_addr), buffer_sz);
    if (m_status == CTF_MSG_ITER_MEDIUM_STATUS_OK) {
        BT_ASSERT(buffer_sz != 0);

        /* New packet offset is old one + old size (in bits) */
        msg_it->buf.packet_offset += buf_size_bits(msg_it);

        /* Restart at the beginning of the new medium buffer */
        msg_it->buf.at = 0;
        msg_it->buf.last_eh_at = SIZE_MAX;

        /* New medium buffer size */
        msg_it->buf.sz = buffer_sz;

        /* New medium buffer address */
        msg_it->buf.addr = buffer_addr;

        BT_CPPLOGD_SPEC(msg_it->logger,
                        "User function returned new bytes: "
                        "packet-offset={}, cur={}, size={}, addr={}",
                        msg_it->buf.packet_offset, msg_it->buf.at, msg_it->buf.sz,
                        fmt::ptr(msg_it->buf.addr));
        BT_CPPLOGT_MEM_SPEC(msg_it->logger, bt2c::makeSpan(buffer_addr, buffer_sz),
                            "Returned bytes at {}:", fmt::ptr(buffer_addr));
    } else if (m_status == CTF_MSG_ITER_MEDIUM_STATUS_EOF) {
        /*
         * User returned end of stream: validate that we're not
         * in the middle of a packet header, packet context, or
         * event.
         */
        if (msg_it->cur_exp_packet_total_size >= 0) {
            if (packet_at(msg_it) == msg_it->cur_exp_packet_total_size) {
                goto end;
            }
        } else {
            if (packet_at(msg_it) == 0) {
                goto end;
            }

            if (msg_it->buf.last_eh_at != SIZE_MAX && msg_it->buf.at == msg_it->buf.last_eh_at) {
                goto end;
            }
        }

        /* All other states are invalid */
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            msg_it->logger,
            "User function returned {}, but message iterator is in an unexpected state: "
            "state={}, cur-packet-size={}, cur={}, "
            "packet-cur={}, last-eh-at={}",
            m_status, msg_it->state, msg_it->cur_exp_packet_total_size, msg_it->buf.at,
            packet_at(msg_it), msg_it->buf.last_eh_at);
        m_status = CTF_MSG_ITER_MEDIUM_STATUS_ERROR;
    } else if (m_status < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "User function failed: "
                                     "status={}",
                                     m_status);
    }

end:
    return msg_iter_status_from_m_status(m_status);
}

static inline enum ctf_msg_iter_status buf_ensure_available_bits(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    if (G_UNLIKELY(buf_available_bits(msg_it) == 0)) {
        /*
         * This _cannot_ return CTF_MSG_ITER_STATUS_OK
         * _and_ no bits.
         */
        status = request_medium_bytes(msg_it);
    }

    return status;
}

static enum ctf_msg_iter_status
read_dscope_begin_state(struct ctf_msg_iter *msg_it, struct ctf_field_class *dscope_fc,
                        enum state done_state, enum state continue_state, bt_field *dscope_field)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    enum bt_bfcr_status bfcr_status;
    size_t consumed_bits;

    msg_it->cur_dscope_field = dscope_field;
    BT_CPPLOGT_SPEC(msg_it->logger, "Starting BFCR: msg-it-addr={}, bfcr-addr={}, fc-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(dscope_fc));
    consumed_bits = bt_bfcr_start(msg_it->bfcr, dscope_fc, msg_it->buf.addr, msg_it->buf.at,
                                  packet_at(msg_it), msg_it->buf.sz, &bfcr_status);
    BT_CPPLOGT_SPEC(msg_it->logger, "BFCR consumed bits: size={}", consumed_bits);

    switch (bfcr_status) {
    case BT_BFCR_STATUS_OK:
        /* Field class was read completely */
        BT_CPPLOGT_SPEC(msg_it->logger, "Field was completely decoded.");
        msg_it->state = done_state;
        break;
    case BT_BFCR_STATUS_EOF:
        BT_CPPLOGT_SPEC(msg_it->logger, "BFCR needs more data to decode field completely.");
        msg_it->state = continue_state;
        break;
    default:
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "BFCR failed to start: msg-it-addr={}, bfcr-addr={}, "
                                     "status={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), bfcr_status);
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

    /* Consume bits now since we know we're not in an error state */
    buf_consume_bits(msg_it, consumed_bits);

end:
    return status;
}

static enum ctf_msg_iter_status read_dscope_continue_state(struct ctf_msg_iter *msg_it,
                                                           enum state done_state)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    enum bt_bfcr_status bfcr_status;
    size_t consumed_bits;

    BT_CPPLOGT_SPEC(msg_it->logger, "Continuing BFCR: msg-it-addr={}, bfcr-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr));

    status = buf_ensure_available_bits(msg_it);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        if (status < 0) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                         "Cannot ensure that buffer has at least one byte: "
                                         "msg-addr={}, status={}",
                                         fmt::ptr(msg_it), status);
        } else {
            BT_CPPLOGT_SPEC(msg_it->logger,
                            "Cannot ensure that buffer has at least one byte: "
                            "msg-addr={}, status={}",
                            fmt::ptr(msg_it), status);
        }

        goto end;
    }

    consumed_bits = bt_bfcr_continue(msg_it->bfcr, msg_it->buf.addr, msg_it->buf.sz, &bfcr_status);
    BT_CPPLOGT_SPEC(msg_it->logger, "BFCR consumed bits: size={}", consumed_bits);

    switch (bfcr_status) {
    case BT_BFCR_STATUS_OK:
        /* Type was read completely. */
        BT_CPPLOGT_SPEC(msg_it->logger, "Field was completely decoded.");
        msg_it->state = done_state;
        break;
    case BT_BFCR_STATUS_EOF:
        /* Stay in this continue state. */
        BT_CPPLOGT_SPEC(msg_it->logger, "BFCR needs more data to decode field completely.");
        break;
    default:
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "BFCR failed to continue: msg-it-addr={}, bfcr-addr={}, "
                                     "status={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), bfcr_status);
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

    /* Consume bits now since we know we're not in an error state. */
    buf_consume_bits(msg_it, consumed_bits);
end:
    return status;
}

static void release_event_dscopes(struct ctf_msg_iter *msg_it)
{
    msg_it->dscopes.event_common_context = NULL;
    msg_it->dscopes.event_spec_context = NULL;
    msg_it->dscopes.event_payload = NULL;
}

static void release_all_dscopes(struct ctf_msg_iter *msg_it)
{
    msg_it->dscopes.stream_packet_context = NULL;

    release_event_dscopes(msg_it);
}

static enum ctf_msg_iter_status switch_packet_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status;

    /*
     * We don't put the stream class here because we need to make
     * sure that all the packets processed by the same message
     * iterator refer to the same stream class (the first one).
     */
    BT_ASSERT(msg_it);

    if (msg_it->cur_exp_packet_total_size != -1) {
        msg_it->cur_packet_offset += msg_it->cur_exp_packet_total_size;
    }

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Switching packet: msg-it-addr={}, cur={}, "
                    "packet-offset={}",
                    fmt::ptr(msg_it), msg_it->buf.at, msg_it->cur_packet_offset);
    stack_clear(msg_it->stack);
    msg_it->meta.ec = NULL;
    BT_PACKET_PUT_REF_AND_RESET(msg_it->packet);
    BT_MESSAGE_PUT_REF_AND_RESET(msg_it->event_msg);
    release_all_dscopes(msg_it);
    msg_it->cur_dscope_field = NULL;

    if (msg_it->medium.medops.switch_packet) {
        enum ctf_msg_iter_medium_status medium_status;

        medium_status = msg_it->medium.medops.switch_packet(msg_it->medium.data);
        if (medium_status == CTF_MSG_ITER_MEDIUM_STATUS_EOF) {
            /* No more packets. */
            msg_it->state = STATE_CHECK_EMIT_MSG_STREAM_END;
            status = CTF_MSG_ITER_STATUS_OK;
            goto end;
        } else if (medium_status != CTF_MSG_ITER_MEDIUM_STATUS_OK) {
            status = msg_iter_status_from_m_status(medium_status);
            goto end;
        }

        /*
         * After the packet switch, the medium might want to give us a
         * different buffer for the new packet.
         */
        status = request_medium_bytes(msg_it);
        if (status != CTF_MSG_ITER_STATUS_OK) {
            goto end;
        }
    }

    /*
     * Adjust current buffer so that addr points to the beginning of the new
     * packet.
     */
    if (msg_it->buf.addr) {
        size_t consumed_bytes = (size_t) (msg_it->buf.at / CHAR_BIT);

        /* Packets are assumed to start on a byte frontier. */
        if (msg_it->buf.at % CHAR_BIT) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                msg_it->logger,
                "Cannot switch packet: current position is not a multiple of 8: "
                "msg-it-addr={}, cur={}",
                fmt::ptr(msg_it), msg_it->buf.at);
            status = CTF_MSG_ITER_STATUS_ERROR;
            goto end;
        }

        msg_it->buf.addr += consumed_bytes;
        msg_it->buf.sz -= consumed_bytes;
        msg_it->buf.at = 0;
        msg_it->buf.packet_offset = 0;
        BT_CPPLOGD_SPEC(msg_it->logger, "Adjusted buffer: addr={}, size={}",
                        fmt::ptr(msg_it->buf.addr), msg_it->buf.sz);
    }

    msg_it->cur_exp_packet_content_size = -1;
    msg_it->cur_exp_packet_total_size = -1;
    msg_it->cur_stream_class_id = -1;
    msg_it->cur_event_class_id = -1;
    msg_it->cur_data_stream_id = -1;
    msg_it->prev_packet_snapshots = msg_it->snapshots;
    msg_it->snapshots.discarded_events = UINT64_C(-1);
    msg_it->snapshots.packets = UINT64_C(-1);
    msg_it->snapshots.beginning_clock = UINT64_C(-1);
    msg_it->snapshots.end_clock = UINT64_C(-1);
    msg_it->state = STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN;

    status = CTF_MSG_ITER_STATUS_OK;
end:
    return status;
}

static enum ctf_msg_iter_status read_packet_header_begin_state(struct ctf_msg_iter *msg_it)
{
    struct ctf_field_class *packet_header_fc = NULL;
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    /*
     * Make sure at least one bit is available for this packet. An
     * empty packet is impossible. If we reach the end of the medium
     * at this point, then it's considered the end of the stream.
     */
    status = buf_ensure_available_bits(msg_it);
    switch (status) {
    case CTF_MSG_ITER_STATUS_OK:
        break;
    case CTF_MSG_ITER_STATUS_EOF:
        status = CTF_MSG_ITER_STATUS_OK;
        msg_it->state = STATE_CHECK_EMIT_MSG_STREAM_END;
        goto end;
    default:
        goto end;
    }

    /* Packet header class is common to the whole trace class. */
    packet_header_fc = msg_it->meta.tc->packet_header_fc;
    if (!packet_header_fc) {
        msg_it->state = STATE_AFTER_TRACE_PACKET_HEADER;
        goto end;
    }

    msg_it->cur_stream_class_id = -1;
    msg_it->cur_event_class_id = -1;
    msg_it->cur_data_stream_id = -1;
    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Decoding packet header field: "
                    "msg-it-addr={}, trace-class-addr={}, fc-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.tc), fmt::ptr(packet_header_fc));
    status = read_dscope_begin_state(msg_it, packet_header_fc, STATE_AFTER_TRACE_PACKET_HEADER,
                                     STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE, NULL);
    if (status < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot decode packet header field: "
                                     "msg-it-addr={}, trace-class-addr={}, "
                                     "fc-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->meta.tc),
                                     fmt::ptr(packet_header_fc));
    }

end:
    return status;
}

static enum ctf_msg_iter_status read_packet_header_continue_state(struct ctf_msg_iter *msg_it)
{
    return read_dscope_continue_state(msg_it, STATE_AFTER_TRACE_PACKET_HEADER);
}

static inline enum ctf_msg_iter_status set_current_stream_class(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    struct ctf_stream_class *new_stream_class = NULL;

    if (msg_it->cur_stream_class_id == -1) {
        /*
         * No current stream class ID field, therefore only one
         * stream class.
         */
        if (msg_it->meta.tc->stream_classes->len != 1) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                         "Need exactly one stream class since there's "
                                         "no stream class ID field: "
                                         "msg-it-addr={}",
                                         fmt::ptr(msg_it));
            status = CTF_MSG_ITER_STATUS_ERROR;
            goto end;
        }

        new_stream_class = (ctf_stream_class *) msg_it->meta.tc->stream_classes->pdata[0];
        msg_it->cur_stream_class_id = new_stream_class->id;
    }

    new_stream_class =
        ctf_trace_class_borrow_stream_class_by_id(msg_it->meta.tc, msg_it->cur_stream_class_id);
    if (!new_stream_class) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            msg_it->logger,
            "No stream class with ID of stream class ID to use in trace class: "
            "msg-it-addr={}, stream-class-id={}, "
            "trace-class-addr={}",
            fmt::ptr(msg_it), msg_it->cur_stream_class_id, fmt::ptr(msg_it->meta.tc));
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

    if (msg_it->meta.sc) {
        if (new_stream_class != msg_it->meta.sc) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                msg_it->logger,
                "Two packets refer to two different stream classes within the same packet sequence: "
                "msg-it-addr={}, prev-stream-class-addr={}, "
                "prev-stream-class-id={}, "
                "next-stream-class-addr={}, "
                "next-stream-class-id={}, "
                "trace-addr={}",
                fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id,
                fmt::ptr(new_stream_class), new_stream_class->id, fmt::ptr(msg_it->meta.tc));
            status = CTF_MSG_ITER_STATUS_ERROR;
            goto end;
        }
    } else {
        msg_it->meta.sc = new_stream_class;
    }

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Set current stream class: "
                    "msg-it-addr={}, stream-class-addr={}, "
                    "stream-class-id={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id);

end:
    return status;
}

static inline enum ctf_msg_iter_status set_current_stream(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    bt_stream *stream = NULL;

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Calling user function (get stream): msg-it-addr={}, "
                    "stream-class-addr={}, stream-class-id={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id);
    stream = msg_it->medium.medops.borrow_stream(msg_it->meta.sc->ir_sc, msg_it->cur_data_stream_id,
                                                 msg_it->medium.data);
    bt_stream_get_ref(stream);
    BT_CPPLOGD_SPEC(msg_it->logger, "User function returned: stream-addr={}", fmt::ptr(stream));
    if (!stream) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            msg_it->logger,
            "User function failed to return a stream object for the given stream class.");
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

    if (msg_it->stream && stream != msg_it->stream) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            msg_it->logger,
            "User function returned a different stream than the previous one for the same sequence of packets.");
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

    BT_STREAM_MOVE_REF(msg_it->stream, stream);

end:
    bt_stream_put_ref(stream);
    return status;
}

static inline enum ctf_msg_iter_status set_current_packet(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    bt_packet *packet = NULL;

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Creating packet from stream: "
                    "msg-it-addr={}, stream-addr={}, "
                    "stream-class-addr={}, "
                    "stream-class-id={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->stream), fmt::ptr(msg_it->meta.sc),
                    msg_it->meta.sc->id);

    /* Create packet */
    BT_ASSERT(msg_it->stream);
    packet = bt_packet_create(msg_it->stream);
    if (!packet) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create packet from stream: "
                                     "msg-it-addr={}, stream-addr={}, "
                                     "stream-class-addr={}, "
                                     "stream-class-id={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->stream),
                                     fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id);
        goto error;
    }

    goto end;

error:
    BT_PACKET_PUT_REF_AND_RESET(packet);
    status = CTF_MSG_ITER_STATUS_ERROR;

end:
    BT_PACKET_MOVE_REF(msg_it->packet, packet);
    return status;
}

static enum ctf_msg_iter_status after_packet_header_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status;

    status = set_current_stream_class(msg_it);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        goto end;
    }

    if (!msg_it->dry_run) {
        status = set_current_stream(msg_it);
        if (status != CTF_MSG_ITER_STATUS_OK) {
            goto end;
        }

        status = set_current_packet(msg_it);
        if (status != CTF_MSG_ITER_STATUS_OK) {
            goto end;
        }
    }

    msg_it->state = STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN;

    status = CTF_MSG_ITER_STATUS_OK;

end:
    return status;
}

static enum ctf_msg_iter_status read_packet_context_begin_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    struct ctf_field_class *packet_context_fc;

    BT_ASSERT(msg_it->meta.sc);
    packet_context_fc = msg_it->meta.sc->packet_context_fc;
    if (!packet_context_fc) {
        BT_CPPLOGD_SPEC(msg_it->logger,
                        "No packet packet context field class in stream class: continuing: "
                        "msg-it-addr={}, stream-class-addr={}, "
                        "stream-class-id={}",
                        fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id);
        msg_it->state = STATE_AFTER_STREAM_PACKET_CONTEXT;
        goto end;
    }

    if (packet_context_fc->in_ir && !msg_it->dry_run) {
        BT_ASSERT(!msg_it->dscopes.stream_packet_context);
        BT_ASSERT(msg_it->packet);
        msg_it->dscopes.stream_packet_context = bt_packet_borrow_context_field(msg_it->packet);
        BT_ASSERT(msg_it->dscopes.stream_packet_context);
    }

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Decoding packet context field: "
                    "msg-it-addr={}, stream-class-addr={}, "
                    "stream-class-id={}, fc-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id,
                    fmt::ptr(packet_context_fc));
    status = read_dscope_begin_state(msg_it, packet_context_fc, STATE_AFTER_STREAM_PACKET_CONTEXT,
                                     STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE,
                                     msg_it->dscopes.stream_packet_context);
    if (status < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot decode packet context field: "
                                     "msg-it-addr={}, stream-class-addr={}, "
                                     "stream-class-id={}, fc-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc),
                                     msg_it->meta.sc->id, fmt::ptr(packet_context_fc));
    }

end:
    return status;
}

static enum ctf_msg_iter_status read_packet_context_continue_state(struct ctf_msg_iter *msg_it)
{
    return read_dscope_continue_state(msg_it, STATE_AFTER_STREAM_PACKET_CONTEXT);
}

static enum ctf_msg_iter_status set_current_packet_content_sizes(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    if (msg_it->cur_exp_packet_total_size == -1) {
        if (msg_it->cur_exp_packet_content_size != -1) {
            msg_it->cur_exp_packet_total_size = msg_it->cur_exp_packet_content_size;
        }
    } else {
        if (msg_it->cur_exp_packet_content_size == -1) {
            msg_it->cur_exp_packet_content_size = msg_it->cur_exp_packet_total_size;
        }
    }

    BT_ASSERT(
        (msg_it->cur_exp_packet_total_size >= 0 && msg_it->cur_exp_packet_content_size >= 0) ||
        (msg_it->cur_exp_packet_total_size < 0 && msg_it->cur_exp_packet_content_size < 0));

    if (msg_it->cur_exp_packet_content_size > msg_it->cur_exp_packet_total_size) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            msg_it->logger,
            "Invalid packet or content size: "
            "content size is greater than packet size: "
            "msg-it-addr={}, packet-context-field-addr={}, "
            "packet-size={}, content-size={}",
            fmt::ptr(msg_it), fmt::ptr(msg_it->dscopes.stream_packet_context),
            msg_it->cur_exp_packet_total_size, msg_it->cur_exp_packet_content_size);
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Set current packet and content sizes: "
                    "msg-it-addr={}, packet-size={}, content-size={}",
                    fmt::ptr(msg_it), msg_it->cur_exp_packet_total_size,
                    msg_it->cur_exp_packet_content_size);

end:
    return status;
}

static enum ctf_msg_iter_status after_packet_context_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status;

    status = set_current_packet_content_sizes(msg_it);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        goto end;
    }

    if (msg_it->emit_stream_beginning_message) {
        msg_it->state = STATE_EMIT_MSG_STREAM_BEGINNING;
    } else {
        msg_it->state = STATE_CHECK_EMIT_MSG_DISCARDED_EVENTS;
    }

end:
    return status;
}

static enum ctf_msg_iter_status read_event_header_begin_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    struct ctf_field_class *event_header_fc = NULL;

    /* Reset the position of the last event header */
    msg_it->buf.last_eh_at = msg_it->buf.at;
    msg_it->cur_event_class_id = -1;

    /* Check if we have some content left */
    if (msg_it->cur_exp_packet_content_size >= 0) {
        if (G_UNLIKELY(packet_at(msg_it) == msg_it->cur_exp_packet_content_size)) {
            /* No more events! */
            BT_CPPLOGD_SPEC(msg_it->logger,
                            "Reached end of packet: msg-it-addr={}, "
                            "cur={}",
                            fmt::ptr(msg_it), packet_at(msg_it));
            msg_it->state = STATE_EMIT_MSG_PACKET_END_MULTI;
            goto end;
        } else if (G_UNLIKELY(packet_at(msg_it) > msg_it->cur_exp_packet_content_size)) {
            /* That's not supposed to happen */
            BT_CPPLOGD_SPEC(
                msg_it->logger,
                "Before decoding event header field: cursor is passed the packet's content: "
                "msg-it-addr={}, content-size={}, "
                "cur={}",
                fmt::ptr(msg_it), msg_it->cur_exp_packet_content_size, packet_at(msg_it));
            status = CTF_MSG_ITER_STATUS_ERROR;
            goto end;
        }
    } else {
        /*
         * "Infinite" content: we're done when the medium has
         * nothing else for us.
         */
        status = buf_ensure_available_bits(msg_it);
        switch (status) {
        case CTF_MSG_ITER_STATUS_OK:
            break;
        case CTF_MSG_ITER_STATUS_EOF:
            status = CTF_MSG_ITER_STATUS_OK;
            msg_it->state = STATE_EMIT_MSG_PACKET_END_SINGLE;
            goto end;
        default:
            goto end;
        }
    }

    release_event_dscopes(msg_it);
    BT_ASSERT(msg_it->meta.sc);
    event_header_fc = msg_it->meta.sc->event_header_fc;
    if (!event_header_fc) {
        msg_it->state = STATE_AFTER_EVENT_HEADER;
        goto end;
    }

    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Decoding event header field: "
                    "msg-it-addr={}, stream-class-addr={}, "
                    "stream-class-id={}, "
                    "fc-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id,
                    fmt::ptr(event_header_fc));
    status = read_dscope_begin_state(msg_it, event_header_fc, STATE_AFTER_EVENT_HEADER,
                                     STATE_DSCOPE_EVENT_HEADER_CONTINUE, NULL);
    if (status < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot decode event header field: "
                                     "msg-it-addr={}, stream-class-addr={}, "
                                     "stream-class-id={}, fc-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc),
                                     msg_it->meta.sc->id, fmt::ptr(event_header_fc));
    }

end:
    return status;
}

static enum ctf_msg_iter_status read_event_header_continue_state(struct ctf_msg_iter *msg_it)
{
    return read_dscope_continue_state(msg_it, STATE_AFTER_EVENT_HEADER);
}

static inline enum ctf_msg_iter_status set_current_event_class(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    struct ctf_event_class *new_event_class = NULL;

    if (msg_it->cur_event_class_id == -1) {
        /*
         * No current event class ID field, therefore only one
         * event class.
         */
        if (msg_it->meta.sc->event_classes->len != 1) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                msg_it->logger,
                "Need exactly one event class since there's no event class ID field: "
                "msg-it-addr={}",
                fmt::ptr(msg_it));
            status = CTF_MSG_ITER_STATUS_ERROR;
            goto end;
        }

        new_event_class = (ctf_event_class *) msg_it->meta.sc->event_classes->pdata[0];
        msg_it->cur_event_class_id = new_event_class->id;
    }

    new_event_class =
        ctf_stream_class_borrow_event_class_by_id(msg_it->meta.sc, msg_it->cur_event_class_id);
    if (!new_event_class) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            msg_it->logger,
            "No event class with ID of event class ID to use in stream class: "
            "msg-it-addr={}, stream-class-id={}, "
            "event-class-id={}, "
            "trace-class-addr={}",
            fmt::ptr(msg_it), msg_it->meta.sc->id, msg_it->cur_event_class_id,
            fmt::ptr(msg_it->meta.tc));
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

    msg_it->meta.ec = new_event_class;
    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Set current event class: "
                    "msg-it-addr={}, event-class-addr={}, "
                    "event-class-id={}, "
                    "event-class-name=\"{}\"",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.ec), msg_it->meta.ec->id,
                    msg_it->meta.ec->name->str);

end:
    return status;
}

static inline enum ctf_msg_iter_status set_current_event_message(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    bt_message *msg = NULL;

    BT_ASSERT_DBG(msg_it->meta.ec);
    BT_ASSERT_DBG(msg_it->packet);
    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Creating event message from event class and packet: "
                    "msg-it-addr={}, ec-addr={}, ec-name=\"{}\", packet-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.ec), msg_it->meta.ec->name->str,
                    fmt::ptr(msg_it->packet));
    BT_ASSERT_DBG(msg_it->self_msg_iter);
    BT_ASSERT_DBG(msg_it->meta.sc);

    if (bt_stream_class_borrow_default_clock_class(msg_it->meta.sc->ir_sc)) {
        msg = bt_message_event_create_with_packet_and_default_clock_snapshot(
            msg_it->self_msg_iter, msg_it->meta.ec->ir_ec, msg_it->packet,
            msg_it->default_clock_snapshot);
    } else {
        msg = bt_message_event_create_with_packet(msg_it->self_msg_iter, msg_it->meta.ec->ir_ec,
                                                  msg_it->packet);
    }

    if (!msg) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create event message: "
                                     "msg-it-addr={}, ec-addr={}, ec-name=\"{}\", "
                                     "packet-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->meta.ec),
                                     msg_it->meta.ec->name->str, fmt::ptr(msg_it->packet));
        goto error;
    }

    goto end;

error:
    BT_MESSAGE_PUT_REF_AND_RESET(msg);
    status = CTF_MSG_ITER_STATUS_ERROR;

end:
    BT_MESSAGE_MOVE_REF(msg_it->event_msg, msg);
    return status;
}

static enum ctf_msg_iter_status after_event_header_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status;

    status = set_current_event_class(msg_it);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        goto end;
    }

    if (G_UNLIKELY(msg_it->dry_run)) {
        goto next_state;
    }

    status = set_current_event_message(msg_it);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        goto end;
    }

    msg_it->event = bt_message_event_borrow_event(msg_it->event_msg);
    BT_ASSERT_DBG(msg_it->event);

next_state:
    msg_it->state = STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN;

end:
    return status;
}

static enum ctf_msg_iter_status read_event_common_context_begin_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    struct ctf_field_class *event_common_context_fc;

    event_common_context_fc = msg_it->meta.sc->event_common_context_fc;
    if (!event_common_context_fc) {
        msg_it->state = STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN;
        goto end;
    }

    if (event_common_context_fc->in_ir && !msg_it->dry_run) {
        BT_ASSERT_DBG(!msg_it->dscopes.event_common_context);
        msg_it->dscopes.event_common_context = bt_event_borrow_common_context_field(msg_it->event);
        BT_ASSERT_DBG(msg_it->dscopes.event_common_context);
    }

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Decoding event common context field: "
                    "msg-it-addr={}, stream-class-addr={}, "
                    "stream-class-id={}, "
                    "fc-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc), msg_it->meta.sc->id,
                    fmt::ptr(event_common_context_fc));
    status = read_dscope_begin_state(
        msg_it, event_common_context_fc, STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN,
        STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE, msg_it->dscopes.event_common_context);
    if (status < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot decode event common context field: "
                                     "msg-it-addr={}, stream-class-addr={}, "
                                     "stream-class-id={}, fc-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->meta.sc),
                                     msg_it->meta.sc->id, fmt::ptr(event_common_context_fc));
    }

end:
    return status;
}

static enum ctf_msg_iter_status
read_event_common_context_continue_state(struct ctf_msg_iter *msg_it)
{
    return read_dscope_continue_state(msg_it, STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN);
}

static enum ctf_msg_iter_status read_event_spec_context_begin_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    struct ctf_field_class *event_spec_context_fc;

    event_spec_context_fc = msg_it->meta.ec->spec_context_fc;
    if (!event_spec_context_fc) {
        msg_it->state = STATE_DSCOPE_EVENT_PAYLOAD_BEGIN;
        goto end;
    }

    if (event_spec_context_fc->in_ir && !msg_it->dry_run) {
        BT_ASSERT_DBG(!msg_it->dscopes.event_spec_context);
        msg_it->dscopes.event_spec_context = bt_event_borrow_specific_context_field(msg_it->event);
        BT_ASSERT_DBG(msg_it->dscopes.event_spec_context);
    }

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Decoding event specific context field: "
                    "msg-it-addr={}, event-class-addr={}, "
                    "event-class-name=\"{}\", event-class-id={}, "
                    "fc-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.ec), msg_it->meta.ec->name->str,
                    msg_it->meta.ec->id, fmt::ptr(event_spec_context_fc));
    status = read_dscope_begin_state(
        msg_it, event_spec_context_fc, STATE_DSCOPE_EVENT_PAYLOAD_BEGIN,
        STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE, msg_it->dscopes.event_spec_context);
    if (status < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot decode event specific context field: "
                                     "msg-it-addr={}, event-class-addr={}, "
                                     "event-class-name=\"{}\", "
                                     "event-class-id={}, fc-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->meta.ec),
                                     msg_it->meta.ec->name->str, msg_it->meta.ec->id,
                                     fmt::ptr(event_spec_context_fc));
    }

end:
    return status;
}

static enum ctf_msg_iter_status read_event_spec_context_continue_state(struct ctf_msg_iter *msg_it)
{
    return read_dscope_continue_state(msg_it, STATE_DSCOPE_EVENT_PAYLOAD_BEGIN);
}

static enum ctf_msg_iter_status read_event_payload_begin_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    struct ctf_field_class *event_payload_fc;

    event_payload_fc = msg_it->meta.ec->payload_fc;
    if (!event_payload_fc) {
        msg_it->state = STATE_EMIT_MSG_EVENT;
        goto end;
    }

    if (event_payload_fc->in_ir && !msg_it->dry_run) {
        BT_ASSERT_DBG(!msg_it->dscopes.event_payload);
        msg_it->dscopes.event_payload = bt_event_borrow_payload_field(msg_it->event);
        BT_ASSERT_DBG(msg_it->dscopes.event_payload);
    }

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Decoding event payload field: "
                    "msg-it-addr={}, event-class-addr={}, "
                    "event-class-name=\"{}\", event-class-id={}, "
                    "fc-addr={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->meta.ec), msg_it->meta.ec->name->str,
                    msg_it->meta.ec->id, fmt::ptr(event_payload_fc));
    status =
        read_dscope_begin_state(msg_it, event_payload_fc, STATE_EMIT_MSG_EVENT,
                                STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE, msg_it->dscopes.event_payload);
    if (status < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot decode event payload field: "
                                     "msg-it-addr={}, event-class-addr={}, "
                                     "event-class-name=\"{}\", "
                                     "event-class-id={}, fc-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->meta.ec),
                                     msg_it->meta.ec->name->str, msg_it->meta.ec->id,
                                     fmt::ptr(event_payload_fc));
    }

end:
    return status;
}

static enum ctf_msg_iter_status read_event_payload_continue_state(struct ctf_msg_iter *msg_it)
{
    return read_dscope_continue_state(msg_it, STATE_EMIT_MSG_EVENT);
}

static enum ctf_msg_iter_status skip_packet_padding_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    size_t bits_to_skip;
    const enum state next_state = STATE_SWITCH_PACKET;

    BT_ASSERT(msg_it->cur_exp_packet_total_size > 0);
    bits_to_skip = msg_it->cur_exp_packet_total_size - packet_at(msg_it);
    if (bits_to_skip == 0) {
        msg_it->state = next_state;
        goto end;
    } else {
        size_t bits_to_consume;

        BT_CPPLOGD_SPEC(msg_it->logger,
                        "Trying to skip {} bits of padding: msg-it-addr={}, size={}", bits_to_skip,
                        fmt::ptr(msg_it), bits_to_skip);
        status = buf_ensure_available_bits(msg_it);
        if (status != CTF_MSG_ITER_STATUS_OK) {
            goto end;
        }

        bits_to_consume = MIN(buf_available_bits(msg_it), bits_to_skip);
        BT_CPPLOGD_SPEC(msg_it->logger, "Skipping {} bits of padding: msg-it-addr={}, size={}",
                        bits_to_consume, fmt::ptr(msg_it), bits_to_consume);
        buf_consume_bits(msg_it, bits_to_consume);
        bits_to_skip = msg_it->cur_exp_packet_total_size - packet_at(msg_it);
        if (bits_to_skip == 0) {
            msg_it->state = next_state;
            goto end;
        }
    }

end:
    return status;
}

static enum ctf_msg_iter_status check_emit_msg_discarded_events(struct ctf_msg_iter *msg_it)
{
    msg_it->state = STATE_EMIT_MSG_DISCARDED_EVENTS;

    if (!msg_it->meta.sc->has_discarded_events) {
        msg_it->state = STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS;
        goto end;
    }

    if (msg_it->prev_packet_snapshots.discarded_events == UINT64_C(-1)) {
        if (msg_it->snapshots.discarded_events == 0 ||
            msg_it->snapshots.discarded_events == UINT64_C(-1)) {
            /*
             * Stream's first packet with no discarded
             * events or no information about discarded
             * events: do not emit.
             */
            msg_it->state = STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS;
        }
    } else {
        /*
         * If the previous packet has a value for this counter,
         * then this counter is defined for the whole stream.
         */
        BT_ASSERT(msg_it->snapshots.discarded_events != UINT64_C(-1));

        if (msg_it->snapshots.discarded_events - msg_it->prev_packet_snapshots.discarded_events ==
            0) {
            /*
             * No discarded events since previous packet: do
             * not emit.
             */
            msg_it->state = STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS;
        }
    }

end:
    return CTF_MSG_ITER_STATUS_OK;
}

static enum ctf_msg_iter_status check_emit_msg_discarded_packets(struct ctf_msg_iter *msg_it)
{
    msg_it->state = STATE_EMIT_MSG_DISCARDED_PACKETS;

    if (!msg_it->meta.sc->has_discarded_packets) {
        msg_it->state = STATE_EMIT_MSG_PACKET_BEGINNING;
        goto end;
    }

    if (msg_it->prev_packet_snapshots.packets == UINT64_C(-1)) {
        /*
         * Stream's first packet or no information about
         * discarded packets: do not emit. In other words, if
         * this is the first packet and its sequence number is
         * not 0, do not consider that packets were previously
         * lost: we might be reading a partial stream (LTTng
         * snapshot for example).
         */
        msg_it->state = STATE_EMIT_MSG_PACKET_BEGINNING;
    } else {
        /*
         * If the previous packet has a value for this counter,
         * then this counter is defined for the whole stream.
         */
        BT_ASSERT(msg_it->snapshots.packets != UINT64_C(-1));

        if (msg_it->snapshots.packets - msg_it->prev_packet_snapshots.packets <= 1) {
            /*
             * No discarded packets since previous packet:
             * do not emit.
             */
            msg_it->state = STATE_EMIT_MSG_PACKET_BEGINNING;
        }
    }

end:
    return CTF_MSG_ITER_STATUS_OK;
}

static inline enum state check_emit_msg_stream_end(struct ctf_msg_iter *msg_it)
{
    enum state next_state;

    if (msg_it->emit_stream_end_message) {
        next_state = STATE_EMIT_MSG_STREAM_END;
    } else {
        next_state = STATE_DONE;
    }

    return next_state;
}

static inline enum ctf_msg_iter_status handle_state(struct ctf_msg_iter *msg_it)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    const enum state state = msg_it->state;

    BT_CPPLOGT_SPEC(msg_it->logger, "Handling state: msg-it-addr={}, state={}", fmt::ptr(msg_it),
                    state);

    // TODO: optimalize!
    switch (state) {
    case STATE_INIT:
        msg_it->state = STATE_SWITCH_PACKET;
        break;
    case STATE_SWITCH_PACKET:
        status = switch_packet_state(msg_it);
        break;
    case STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN:
        status = read_packet_header_begin_state(msg_it);
        break;
    case STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE:
        status = read_packet_header_continue_state(msg_it);
        break;
    case STATE_AFTER_TRACE_PACKET_HEADER:
        status = after_packet_header_state(msg_it);
        break;
    case STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN:
        status = read_packet_context_begin_state(msg_it);
        break;
    case STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE:
        status = read_packet_context_continue_state(msg_it);
        break;
    case STATE_AFTER_STREAM_PACKET_CONTEXT:
        status = after_packet_context_state(msg_it);
        break;
    case STATE_EMIT_MSG_STREAM_BEGINNING:
        msg_it->state = STATE_CHECK_EMIT_MSG_DISCARDED_EVENTS;
        break;
    case STATE_CHECK_EMIT_MSG_DISCARDED_EVENTS:
        status = check_emit_msg_discarded_events(msg_it);
        break;
    case STATE_EMIT_MSG_DISCARDED_EVENTS:
        msg_it->state = STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS;
        break;
    case STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS:
        status = check_emit_msg_discarded_packets(msg_it);
        break;
    case STATE_EMIT_MSG_DISCARDED_PACKETS:
        msg_it->state = STATE_EMIT_MSG_PACKET_BEGINNING;
        break;
    case STATE_EMIT_MSG_PACKET_BEGINNING:
        msg_it->state = STATE_DSCOPE_EVENT_HEADER_BEGIN;
        break;
    case STATE_DSCOPE_EVENT_HEADER_BEGIN:
        status = read_event_header_begin_state(msg_it);
        break;
    case STATE_DSCOPE_EVENT_HEADER_CONTINUE:
        status = read_event_header_continue_state(msg_it);
        break;
    case STATE_AFTER_EVENT_HEADER:
        status = after_event_header_state(msg_it);
        break;
    case STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN:
        status = read_event_common_context_begin_state(msg_it);
        break;
    case STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE:
        status = read_event_common_context_continue_state(msg_it);
        break;
    case STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN:
        status = read_event_spec_context_begin_state(msg_it);
        break;
    case STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE:
        status = read_event_spec_context_continue_state(msg_it);
        break;
    case STATE_DSCOPE_EVENT_PAYLOAD_BEGIN:
        status = read_event_payload_begin_state(msg_it);
        break;
    case STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE:
        status = read_event_payload_continue_state(msg_it);
        break;
    case STATE_EMIT_MSG_EVENT:
        msg_it->state = STATE_DSCOPE_EVENT_HEADER_BEGIN;
        break;
    case STATE_EMIT_QUEUED_MSG_EVENT:
        msg_it->state = STATE_EMIT_MSG_EVENT;
        break;
    case STATE_SKIP_PACKET_PADDING:
        status = skip_packet_padding_state(msg_it);
        break;
    case STATE_EMIT_MSG_PACKET_END_MULTI:
        msg_it->state = STATE_SKIP_PACKET_PADDING;
        break;
    case STATE_EMIT_MSG_PACKET_END_SINGLE:
        msg_it->state = STATE_EMIT_MSG_STREAM_END;
        break;
    case STATE_EMIT_QUEUED_MSG_PACKET_END:
        msg_it->state = STATE_EMIT_MSG_PACKET_END_SINGLE;
        break;
    case STATE_CHECK_EMIT_MSG_STREAM_END:
        msg_it->state = check_emit_msg_stream_end(msg_it);
        break;
    case STATE_EMIT_MSG_STREAM_END:
        msg_it->state = STATE_DONE;
        break;
    case STATE_DONE:
        break;
    default:
        BT_CPPLOGF_SPEC(msg_it->logger,
                        "Unknown CTF plugin message iterator state: "
                        "msg-it-addr={}, state={}",
                        fmt::ptr(msg_it), msg_it->state);
        bt_common_abort();
    }

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Handled state: msg-it-addr={}, status={}, "
                    "prev-state={}, cur-state={}",
                    fmt::ptr(msg_it), status, state, msg_it->state);
    return status;
}

void ctf_msg_iter_reset_for_next_stream_file(struct ctf_msg_iter *msg_it)
{
    BT_ASSERT(msg_it);
    BT_CPPLOGD_SPEC(msg_it->logger, "Resetting message iterator: addr={}", fmt::ptr(msg_it));
    stack_clear(msg_it->stack);
    msg_it->meta.sc = NULL;
    msg_it->meta.ec = NULL;
    BT_PACKET_PUT_REF_AND_RESET(msg_it->packet);
    BT_STREAM_PUT_REF_AND_RESET(msg_it->stream);
    BT_MESSAGE_PUT_REF_AND_RESET(msg_it->event_msg);
    release_all_dscopes(msg_it);
    msg_it->cur_dscope_field = NULL;

    msg_it->buf.addr = NULL;
    msg_it->buf.sz = 0;
    msg_it->buf.at = 0;
    msg_it->buf.last_eh_at = SIZE_MAX;
    msg_it->buf.packet_offset = 0;
    msg_it->state = STATE_INIT;
    msg_it->cur_exp_packet_content_size = -1;
    msg_it->cur_exp_packet_total_size = -1;
    msg_it->cur_packet_offset = -1;
    msg_it->cur_event_class_id = -1;
    msg_it->snapshots.beginning_clock = UINT64_C(-1);
    msg_it->snapshots.end_clock = UINT64_C(-1);
}

/**
 * Resets the internal state of a CTF message iterator.
 */
void ctf_msg_iter_reset(struct ctf_msg_iter *msg_it)
{
    ctf_msg_iter_reset_for_next_stream_file(msg_it);
    msg_it->cur_stream_class_id = -1;
    msg_it->cur_data_stream_id = -1;
    msg_it->snapshots.discarded_events = UINT64_C(-1);
    msg_it->snapshots.packets = UINT64_C(-1);
    msg_it->prev_packet_snapshots.discarded_events = UINT64_C(-1);
    msg_it->prev_packet_snapshots.packets = UINT64_C(-1);
    msg_it->prev_packet_snapshots.beginning_clock = UINT64_C(-1);
    msg_it->prev_packet_snapshots.end_clock = UINT64_C(-1);
    msg_it->emit_stream_beginning_message = true;
    msg_it->emit_stream_end_message = false;
}

static bt_field *borrow_next_field(struct ctf_msg_iter *msg_it)
{
    bt_field *next_field = NULL;
    bt_field *base_field;
    const bt_field_class *base_fc;
    bt_field_class_type base_fc_type;
    size_t index;

    BT_ASSERT_DBG(!stack_empty(msg_it->stack));
    index = stack_top(msg_it->stack)->index;
    base_field = stack_top(msg_it->stack)->base;
    BT_ASSERT_DBG(base_field);
    base_fc = bt_field_borrow_class_const(base_field);
    BT_ASSERT_DBG(base_fc);
    base_fc_type = bt_field_class_get_type(base_fc);

    if (base_fc_type == BT_FIELD_CLASS_TYPE_STRUCTURE) {
        BT_ASSERT_DBG(index < bt_field_class_structure_get_member_count(
                                  bt_field_borrow_class_const(base_field)));
        next_field = bt_field_structure_borrow_member_field_by_index(base_field, index);
    } else if (bt_field_class_type_is(base_fc_type, BT_FIELD_CLASS_TYPE_ARRAY)) {
        BT_ASSERT_DBG(index < bt_field_array_get_length(base_field));
        next_field = bt_field_array_borrow_element_field_by_index(base_field, index);
    } else if (bt_field_class_type_is(base_fc_type, BT_FIELD_CLASS_TYPE_VARIANT)) {
        BT_ASSERT_DBG(index == 0);
        next_field = bt_field_variant_borrow_selected_option_field(base_field);
    } else {
        bt_common_abort();
    }

    BT_ASSERT_DBG(next_field);
    return next_field;
}

static void update_default_clock(struct ctf_msg_iter *msg_it, uint64_t new_val,
                                 uint64_t new_val_size)
{
    uint64_t new_val_mask;
    uint64_t cur_value_masked;

    BT_ASSERT_DBG(new_val_size > 0);

    /*
     * Special case for a 64-bit new value, which is the limit
     * of a clock value as of this version: overwrite the
     * current value directly.
     */
    if (new_val_size == 64) {
        msg_it->default_clock_snapshot = new_val;
        goto end;
    }

    new_val_mask = (1ULL << new_val_size) - 1;
    cur_value_masked = msg_it->default_clock_snapshot & new_val_mask;

    if (new_val < cur_value_masked) {
        /*
         * It looks like a wrap happened on the number of bits
         * of the requested new value. Assume that the clock
         * value wrapped only one time.
         */
        msg_it->default_clock_snapshot += new_val_mask + 1;
    }

    /* Clear the low bits of the current clock value. */
    msg_it->default_clock_snapshot &= ~new_val_mask;

    /* Set the low bits of the current clock value. */
    msg_it->default_clock_snapshot |= new_val;

end:
    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Updated default clock's value from integer field's value: "
                    "value={}",
                    msg_it->default_clock_snapshot);
}

/*
 * Ensure the message iterator's `stored_values` array is large enough to
 * accommodate `storing_index`.
 *
 * We may need more slots in the array than initially allocated if more
 * metadata arrives along the way.
 */
static void ensure_stored_values_size(ctf_msg_iter *msg_it, uint64_t storing_index)
{
    if (G_UNLIKELY(storing_index >= msg_it->stored_values->len)) {
        g_array_set_size(msg_it->stored_values, msg_it->meta.tc->stored_value_count);
    }
}

static enum bt_bfcr_status bfcr_unsigned_int_cb(uint64_t value, struct ctf_field_class *fc,
                                                void *data)
{
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;

    bt_field *field = NULL;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Unsigned integer function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}, value={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir,
                    value);

    ctf_field_class_int *int_fc = ctf_field_class_as_int(fc);

    if (G_LIKELY(int_fc->meaning == CTF_FIELD_CLASS_MEANING_NONE)) {
        goto update_def_clock;
    }

    switch (int_fc->meaning) {
    case CTF_FIELD_CLASS_MEANING_EVENT_CLASS_ID:
        msg_it->cur_event_class_id = value;
        break;
    case CTF_FIELD_CLASS_MEANING_DATA_STREAM_ID:
        msg_it->cur_data_stream_id = value;
        break;
    case CTF_FIELD_CLASS_MEANING_PACKET_BEGINNING_TIME:
        msg_it->snapshots.beginning_clock = value;
        break;
    case CTF_FIELD_CLASS_MEANING_PACKET_END_TIME:
        msg_it->snapshots.end_clock = value;
        break;
    case CTF_FIELD_CLASS_MEANING_STREAM_CLASS_ID:
        msg_it->cur_stream_class_id = value;
        break;
    case CTF_FIELD_CLASS_MEANING_MAGIC:
        if (value != 0xc1fc1fc1) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                         "Invalid CTF magic number: msg-it-addr={}, magic={}",
                                         fmt::ptr(msg_it), value);
            status = BT_BFCR_STATUS_ERROR;
            goto end;
        }

        break;
    case CTF_FIELD_CLASS_MEANING_PACKET_COUNTER_SNAPSHOT:
        msg_it->snapshots.packets = value;
        break;
    case CTF_FIELD_CLASS_MEANING_DISC_EV_REC_COUNTER_SNAPSHOT:
        msg_it->snapshots.discarded_events = value;
        break;
    case CTF_FIELD_CLASS_MEANING_EXP_PACKET_TOTAL_SIZE:
        msg_it->cur_exp_packet_total_size = value;
        break;
    case CTF_FIELD_CLASS_MEANING_EXP_PACKET_CONTENT_SIZE:
        msg_it->cur_exp_packet_content_size = value;
        break;
    default:
        bt_common_abort();
    }

update_def_clock:
    if (G_UNLIKELY(int_fc->mapped_clock_class)) {
        update_default_clock(msg_it, value, int_fc->base.size);
    }

    if (G_UNLIKELY(int_fc->storing_index >= 0)) {
        ensure_stored_values_size(msg_it, int_fc->storing_index);
        bt_g_array_index(msg_it->stored_values, uint64_t, (uint64_t) int_fc->storing_index) = value;
    }

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    field = borrow_next_field(msg_it);
    BT_ASSERT_DBG(field);
    BT_ASSERT_DBG(bt_field_borrow_class_const(field) == fc->ir_fc);
    BT_ASSERT_DBG(bt_field_class_type_is(bt_field_get_class_type(field),
                                         BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER));
    bt_field_integer_unsigned_set_value(field, value);
    stack_top(msg_it->stack)->index++;

end:
    return status;
}

static enum bt_bfcr_status bfcr_unsigned_int_char_cb(uint64_t value, struct ctf_field_class *fc,
                                                     void *data)
{
    int ret;
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    bt_field *string_field = NULL;
    char str[2] = {'\0', '\0'};

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Unsigned integer character function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}, value={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir,
                    value);

    ctf_field_class_int *int_fc = ctf_field_class_as_int(fc);
    BT_ASSERT_DBG(int_fc->meaning == CTF_FIELD_CLASS_MEANING_NONE);
    BT_ASSERT_DBG(!int_fc->mapped_clock_class);
    BT_ASSERT_DBG(int_fc->storing_index < 0);

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    if (msg_it->done_filling_string) {
        goto end;
    }

    if (value == 0) {
        msg_it->done_filling_string = true;
        goto end;
    }

    string_field = stack_top(msg_it->stack)->base;
    BT_ASSERT_DBG(bt_field_get_class_type(string_field) == BT_FIELD_CLASS_TYPE_STRING);

    /* Append character */
    str[0] = (char) value;
    ret = bt_field_string_append_with_length(string_field, str, 1);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot append character to string field's value: "
                                     "msg-it-addr={}, field-addr={}, ret={}",
                                     fmt::ptr(msg_it), fmt::ptr(string_field), ret);
        status = BT_BFCR_STATUS_ERROR;
        goto end;
    }

end:
    return status;
}

static enum bt_bfcr_status bfcr_signed_int_cb(int64_t value, struct ctf_field_class *fc, void *data)
{
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    bt_field *field = NULL;
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Signed integer function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}, value={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir,
                    value);

    ctf_field_class_int *int_fc = ctf_field_class_as_int(fc);
    BT_ASSERT_DBG(int_fc->meaning == CTF_FIELD_CLASS_MEANING_NONE);

    if (G_UNLIKELY(int_fc->storing_index >= 0)) {
        ensure_stored_values_size(msg_it, int_fc->storing_index);
        bt_g_array_index(msg_it->stored_values, uint64_t, (uint64_t) int_fc->storing_index) =
            (uint64_t) value;
    }

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    field = borrow_next_field(msg_it);
    BT_ASSERT_DBG(field);
    BT_ASSERT_DBG(bt_field_borrow_class_const(field) == fc->ir_fc);
    BT_ASSERT_DBG(
        bt_field_class_type_is(bt_field_get_class_type(field), BT_FIELD_CLASS_TYPE_SIGNED_INTEGER));
    bt_field_integer_signed_set_value(field, value);
    stack_top(msg_it->stack)->index++;

end:
    return status;
}

static enum bt_bfcr_status bfcr_floating_point_cb(double value, struct ctf_field_class *fc,
                                                  void *data)
{
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    bt_field *field = NULL;
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;
    bt_field_class_type type;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Floating point number function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}, value={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir,
                    value);

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    field = borrow_next_field(msg_it);
    type = bt_field_get_class_type(field);
    BT_ASSERT_DBG(field);
    BT_ASSERT_DBG(bt_field_borrow_class_const(field) == fc->ir_fc);
    BT_ASSERT_DBG(bt_field_class_type_is(type, BT_FIELD_CLASS_TYPE_REAL));

    if (type == BT_FIELD_CLASS_TYPE_SINGLE_PRECISION_REAL) {
        bt_field_real_single_precision_set_value(field, (float) value);
    } else {
        bt_field_real_double_precision_set_value(field, value);
    }
    stack_top(msg_it->stack)->index++;

end:
    return status;
}

static enum bt_bfcr_status bfcr_string_begin_cb(struct ctf_field_class *fc, void *data)
{
    bt_field *field = NULL;
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "String (beginning) function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir);

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    field = borrow_next_field(msg_it);
    BT_ASSERT_DBG(field);
    BT_ASSERT_DBG(bt_field_borrow_class_const(field) == fc->ir_fc);
    BT_ASSERT_DBG(bt_field_get_class_type(field) == BT_FIELD_CLASS_TYPE_STRING);
    bt_field_string_clear(field);

    /*
     * Push on stack. Not a compound class per se, but we know that
     * only bfcr_string_cb() may be called between this call and a
     * subsequent call to bfcr_string_end_cb().
     */
    stack_push(msg_it->stack, field);

end:
    return BT_BFCR_STATUS_OK;
}

static enum bt_bfcr_status bfcr_string_cb(const char *value, size_t len, struct ctf_field_class *fc,
                                          void *data)
{
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    bt_field *field = NULL;
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;
    int ret;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "String (substring) function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}, string-length={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir,
                    len);

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    field = stack_top(msg_it->stack)->base;
    BT_ASSERT_DBG(field);

    /* Append current substring */
    ret = bt_field_string_append_with_length(field, value, len);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot append substring to string field's value: "
                                     "msg-it-addr={}, field-addr={}, string-length={}, "
                                     "ret={}",
                                     fmt::ptr(msg_it), fmt::ptr(field), len, ret);
        status = BT_BFCR_STATUS_ERROR;
        goto end;
    }

end:
    return status;
}

static enum bt_bfcr_status bfcr_string_end_cb(struct ctf_field_class *fc, void *data)
{
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "String (end) function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir);

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    /* Pop string field */
    stack_pop(msg_it->stack);

    /* Go to next field */
    stack_top(msg_it->stack)->index++;

end:
    return BT_BFCR_STATUS_OK;
}

static enum bt_bfcr_status bfcr_compound_begin_cb(struct ctf_field_class *fc, void *data)
{
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;
    bt_field *field;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Compound (beginning) function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir);

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    /* Borrow field */
    if (stack_empty(msg_it->stack)) {
        /* Root: already set by read_dscope_begin_state() */
        field = msg_it->cur_dscope_field;
    } else {
        field = borrow_next_field(msg_it);
        BT_ASSERT_DBG(field);
    }

    /* Push field */
    BT_ASSERT_DBG(field);
    BT_ASSERT_DBG(bt_field_borrow_class_const(field) == fc->ir_fc);
    stack_push(msg_it->stack, field);

    /*
     * Change BFCR "unsigned int" callback if it's a text
     * array/sequence.
     */
    if (fc->type == CTF_FIELD_CLASS_TYPE_ARRAY || fc->type == CTF_FIELD_CLASS_TYPE_SEQUENCE) {
        ctf_field_class_array_base *array_fc = ctf_field_class_as_array_base(fc);

        if (array_fc->is_text) {
            BT_ASSERT_DBG(bt_field_get_class_type(field) == BT_FIELD_CLASS_TYPE_STRING);
            msg_it->done_filling_string = false;
            bt_field_string_clear(field);
            bt_bfcr_set_unsigned_int_cb(msg_it->bfcr, bfcr_unsigned_int_char_cb);
        }
    }

end:
    return BT_BFCR_STATUS_OK;
}

static enum bt_bfcr_status bfcr_compound_end_cb(struct ctf_field_class *fc, void *data)
{
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;

    BT_CPPLOGT_SPEC(msg_it->logger,
                    "Compound (end) function called from BFCR: "
                    "msg-it-addr={}, bfcr-addr={}, fc-addr={}, "
                    "fc-type={}, fc-in-ir={}",
                    fmt::ptr(msg_it), fmt::ptr(msg_it->bfcr), fmt::ptr(fc), fc->type, fc->in_ir);

    if (G_UNLIKELY(!fc->in_ir || msg_it->dry_run)) {
        goto end;
    }

    BT_ASSERT_DBG(!stack_empty(msg_it->stack));
    BT_ASSERT_DBG(bt_field_borrow_class_const(stack_top(msg_it->stack)->base) == fc->ir_fc);

    /*
     * Reset BFCR "unsigned int" callback if it's a text
     * array/sequence.
     */
    if (fc->type == CTF_FIELD_CLASS_TYPE_ARRAY || fc->type == CTF_FIELD_CLASS_TYPE_SEQUENCE) {
        ctf_field_class_array_base *array_fc = ctf_field_class_as_array_base(fc);

        if (array_fc->is_text) {
            BT_ASSERT_DBG(bt_field_get_class_type(stack_top(msg_it->stack)->base) ==
                          BT_FIELD_CLASS_TYPE_STRING);
            bt_bfcr_set_unsigned_int_cb(msg_it->bfcr, bfcr_unsigned_int_cb);
        }
    }

    /* Pop stack */
    stack_pop(msg_it->stack);

    /* If the stack is not empty, increment the base's index */
    if (!stack_empty(msg_it->stack)) {
        stack_top(msg_it->stack)->index++;
    }

end:
    return BT_BFCR_STATUS_OK;
}

static int64_t bfcr_get_sequence_length_cb(struct ctf_field_class *fc, void *data)
{
    bt_field *seq_field;
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;
    struct ctf_field_class_sequence *seq_fc = ctf_field_class_as_sequence(fc);
    int64_t length;
    int ret;

    length =
        (uint64_t) bt_g_array_index(msg_it->stored_values, uint64_t, seq_fc->stored_length_index);

    if (G_UNLIKELY(msg_it->dry_run)) {
        goto end;
    }

    seq_field = stack_top(msg_it->stack)->base;
    BT_ASSERT_DBG(seq_field);

    /*
     * bfcr_get_sequence_length_cb() also gets called back for a
     * text sequence, but the destination field is a string field.
     * Only set the field's sequence length if the destination field
     * is a sequence field.
     */
    if (!seq_fc->base.is_text) {
        BT_ASSERT_DBG(bt_field_class_type_is(bt_field_get_class_type(seq_field),
                                             BT_FIELD_CLASS_TYPE_DYNAMIC_ARRAY));
        ret = bt_field_array_dynamic_set_length(seq_field, (uint64_t) length);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                         "Cannot set dynamic array field's length field: "
                                         "msg-it-addr={}, field-addr={}, "
                                         "length={}",
                                         fmt::ptr(msg_it), fmt::ptr(seq_field), length);
            length = -1;
        }
    }

end:
    return length;
}

static struct ctf_field_class *
bfcr_borrow_variant_selected_field_class_cb(struct ctf_field_class *fc, void *data)
{
    int ret;
    uint64_t i;
    int64_t option_index = -1;
    ctf_msg_iter *msg_it = (ctf_msg_iter *) data;
    ctf_field_class_variant *var_fc = ctf_field_class_as_variant(fc);
    struct ctf_named_field_class *selected_option = NULL;
    struct ctf_field_class *ret_fc = NULL;
    union
    {
        uint64_t u;
        int64_t i;
    } tag;

    /* Get variant's tag */
    tag.u = bt_g_array_index(msg_it->stored_values, uint64_t, var_fc->stored_tag_index);

    /*
     * Check each range to find the selected option's index.
     */
    if (var_fc->tag_fc->base.is_signed) {
        for (i = 0; i < var_fc->ranges->len; i++) {
            struct ctf_field_class_variant_range *range =
                ctf_field_class_variant_borrow_range_by_index(var_fc, i);

            if (tag.i >= range->range.lower.i && tag.i <= range->range.upper.i) {
                option_index = (int64_t) range->option_index;
                break;
            }
        }
    } else {
        for (i = 0; i < var_fc->ranges->len; i++) {
            struct ctf_field_class_variant_range *range =
                ctf_field_class_variant_borrow_range_by_index(var_fc, i);

            if (tag.u >= range->range.lower.u && tag.u <= range->range.upper.u) {
                option_index = (int64_t) range->option_index;
                break;
            }
        }
    }

    if (option_index < 0) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot find variant field class's option: "
                                     "msg-it-addr={}, var-fc-addr={}, u-tag={}, "
                                     "i-tag={}",
                                     fmt::ptr(msg_it), fmt::ptr(var_fc), tag.u, tag.i);
        ret_fc = NULL;
        goto end;
    }

    selected_option =
        ctf_field_class_variant_borrow_option_by_index(var_fc, (uint64_t) option_index);

    if (selected_option->fc->in_ir && !msg_it->dry_run) {
        bt_field *var_field = stack_top(msg_it->stack)->base;

        ret = bt_field_variant_select_option_by_index(var_field, option_index);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                         "Cannot select variant field's option field: "
                                         "msg-it-addr={}, var-field-addr={}, "
                                         "opt-index={}",
                                         fmt::ptr(msg_it), fmt::ptr(var_field), option_index);
            ret_fc = NULL;
            goto end;
        }
    }

    ret_fc = selected_option->fc;

end:
    return ret_fc;
}

static bt_message *create_msg_stream_beginning(struct ctf_msg_iter *msg_it)
{
    bt_message *msg;

    BT_ASSERT(msg_it->stream);
    BT_ASSERT(msg_it->self_msg_iter);
    msg = bt_message_stream_beginning_create(msg_it->self_msg_iter, msg_it->stream);
    if (!msg) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create stream beginning message: "
                                     "msg-it-addr={}, stream-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->stream));
    }

    return msg;
}

static bt_message *create_msg_stream_end(struct ctf_msg_iter *msg_it)
{
    bt_message *msg;

    if (!msg_it->stream) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create stream end message because stream is NULL: "
                                     "msg-it-addr={}",
                                     fmt::ptr(msg_it));
        msg = NULL;
        goto end;
    }

    BT_ASSERT(msg_it->self_msg_iter);
    msg = bt_message_stream_end_create(msg_it->self_msg_iter, msg_it->stream);
    if (!msg) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create stream end message: "
                                     "msg-it-addr={}, stream-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->stream));
    }

end:
    return msg;
}

static bt_message *create_msg_packet_beginning(struct ctf_msg_iter *msg_it, bool use_default_cs)
{
    bt_message *msg;
    const bt_stream_class *sc = msg_it->meta.sc->ir_sc;

    BT_ASSERT(msg_it->packet);
    BT_ASSERT(sc);
    BT_ASSERT(msg_it->self_msg_iter);

    if (msg_it->meta.sc->packets_have_ts_begin) {
        BT_ASSERT(msg_it->snapshots.beginning_clock != UINT64_C(-1));
        uint64_t raw_cs_value;

        /*
         * Either use the decoded packet `timestamp_begin` field or the
         * current stream's default clock_snapshot.
         */
        if (use_default_cs) {
            raw_cs_value = msg_it->default_clock_snapshot;
        } else {
            raw_cs_value = msg_it->snapshots.beginning_clock;
        }

        msg = bt_message_packet_beginning_create_with_default_clock_snapshot(
            msg_it->self_msg_iter, msg_it->packet, raw_cs_value);
    } else {
        msg = bt_message_packet_beginning_create(msg_it->self_msg_iter, msg_it->packet);
    }

    if (!msg) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create packet beginning message: "
                                     "msg-it-addr={}, packet-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->packet));
        goto end;
    }

end:
    return msg;
}

static bt_message *emit_delayed_packet_beg_msg(struct ctf_msg_iter *msg_it)
{
    bool packet_beg_ts_need_fix_up;

    msg_it->emit_delayed_packet_beginning_msg = false;

    /*
     * Only fix the packet's timestamp_begin if it's larger than the first
     * event of the packet. If there was no event in the packet, the
     * `default_clock_snapshot` field will be either equal or greater than
     * `snapshots.beginning_clock` so there is not fix needed.
     */
    packet_beg_ts_need_fix_up = msg_it->default_clock_snapshot < msg_it->snapshots.beginning_clock;

    /* create_msg_packet_beginning() logs errors */
    return create_msg_packet_beginning(msg_it, packet_beg_ts_need_fix_up);
}

static bt_message *create_msg_packet_end(struct ctf_msg_iter *msg_it)
{
    bt_message *msg;
    bool update_default_cs = true;

    if (!msg_it->packet) {
        msg = NULL;
        goto end;
    }

    /*
     * Check if we need to emit the delayed packet
     * beginning message instead of the packet end message.
     */
    if (G_UNLIKELY(msg_it->emit_delayed_packet_beginning_msg)) {
        msg = emit_delayed_packet_beg_msg(msg_it);
        /* Don't forget to emit the packet end message. */
        msg_it->state = STATE_EMIT_QUEUED_MSG_PACKET_END;
        goto end;
    }

    /* Check if may be affected by lttng-crash timestamp_end quirk. */
    if (G_UNLIKELY(msg_it->meta.tc->quirks.lttng_crash)) {
        /*
         * Check if the `timestamp_begin` field is non-zero but
         * `timestamp_end` is zero. It means the trace is affected by
         * the lttng-crash packet `timestamp_end` quirk and must be
         * fixed up by omitting to update the default clock snapshot to
         * the `timestamp_end` as is typically done.
         */
        if (msg_it->snapshots.beginning_clock != 0 && msg_it->snapshots.end_clock == 0) {
            update_default_cs = false;
        }
    }

    /*
     * Check if may be affected by lttng event-after-packet `timestamp_end`
     * quirk.
     */
    if (msg_it->meta.tc->quirks.lttng_event_after_packet) {
        /*
         * Check if `timestamp_end` is smaller then the current
         * default_clock_snapshot (which is set to the last event
         * decoded). It means the trace is affected by the lttng
         * `event-after-packet` packet `timestamp_end` quirk and must
         * be fixed up by omitting to update the default clock snapshot
         * to the `timestamp_end` as is typically done.
         */
        if (msg_it->snapshots.end_clock < msg_it->default_clock_snapshot) {
            update_default_cs = false;
        }
    }

    /* Update default clock from packet's end time. */
    if (msg_it->snapshots.end_clock != UINT64_C(-1) && update_default_cs) {
        msg_it->default_clock_snapshot = msg_it->snapshots.end_clock;
    }

    BT_ASSERT(msg_it->self_msg_iter);

    if (msg_it->meta.sc->packets_have_ts_end) {
        BT_ASSERT(msg_it->snapshots.end_clock != UINT64_C(-1));
        msg = bt_message_packet_end_create_with_default_clock_snapshot(
            msg_it->self_msg_iter, msg_it->packet, msg_it->default_clock_snapshot);
    } else {
        msg = bt_message_packet_end_create(msg_it->self_msg_iter, msg_it->packet);
    }

    if (!msg) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create packet end message: "
                                     "msg-it-addr={}, packet-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->packet));
        goto end;
    }

    BT_PACKET_PUT_REF_AND_RESET(msg_it->packet);

end:
    return msg;
}

static bt_message *create_msg_discarded_events(struct ctf_msg_iter *msg_it)
{
    bt_message *msg;
    uint64_t beginning_raw_value = UINT64_C(-1);
    uint64_t end_raw_value = UINT64_C(-1);

    BT_ASSERT(msg_it->self_msg_iter);
    BT_ASSERT(msg_it->stream);
    BT_ASSERT(msg_it->meta.sc->has_discarded_events);

    if (msg_it->meta.sc->discarded_events_have_default_cs) {
        if (msg_it->prev_packet_snapshots.discarded_events == UINT64_C(-1)) {
            /*
             * We discarded events, but before (and possibly
             * including) the current packet: use this packet's time
             * range, and do not have a specific count.
             */
            beginning_raw_value = msg_it->snapshots.beginning_clock;
            end_raw_value = msg_it->snapshots.end_clock;
        } else {
            beginning_raw_value = msg_it->prev_packet_snapshots.end_clock;
            end_raw_value = msg_it->snapshots.end_clock;
        }

        BT_ASSERT(beginning_raw_value != UINT64_C(-1));
        BT_ASSERT(end_raw_value != UINT64_C(-1));
        msg = bt_message_discarded_events_create_with_default_clock_snapshots(
            msg_it->self_msg_iter, msg_it->stream, beginning_raw_value, end_raw_value);
    } else {
        msg = bt_message_discarded_events_create(msg_it->self_msg_iter, msg_it->stream);
    }

    if (!msg) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create discarded events message: "
                                     "msg-it-addr={}, stream-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->stream));
        goto end;
    }

    if (msg_it->prev_packet_snapshots.discarded_events != UINT64_C(-1)) {
        bt_message_discarded_events_set_count(msg,
                                              msg_it->snapshots.discarded_events -
                                                  msg_it->prev_packet_snapshots.discarded_events);
    }

end:
    return msg;
}

static bt_message *create_msg_discarded_packets(struct ctf_msg_iter *msg_it)
{
    bt_message *msg;

    BT_ASSERT(msg_it->self_msg_iter);
    BT_ASSERT(msg_it->stream);
    BT_ASSERT(msg_it->meta.sc->has_discarded_packets);
    BT_ASSERT(msg_it->prev_packet_snapshots.packets != UINT64_C(-1));

    if (msg_it->meta.sc->discarded_packets_have_default_cs) {
        BT_ASSERT(msg_it->prev_packet_snapshots.end_clock != UINT64_C(-1));
        BT_ASSERT(msg_it->snapshots.beginning_clock != UINT64_C(-1));
        msg = bt_message_discarded_packets_create_with_default_clock_snapshots(
            msg_it->self_msg_iter, msg_it->stream, msg_it->prev_packet_snapshots.end_clock,
            msg_it->snapshots.beginning_clock);
    } else {
        msg = bt_message_discarded_packets_create(msg_it->self_msg_iter, msg_it->stream);
    }

    if (!msg) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Cannot create discarded packets message: "
                                     "msg-it-addr={}, stream-addr={}",
                                     fmt::ptr(msg_it), fmt::ptr(msg_it->stream));
        goto end;
    }

    bt_message_discarded_packets_set_count(msg, msg_it->snapshots.packets -
                                                    msg_it->prev_packet_snapshots.packets - 1);

end:
    return msg;
}

ctf_msg_iter_up ctf_msg_iter_create(struct ctf_trace_class *tc, size_t max_request_sz,
                                    struct ctf_msg_iter_medium_ops medops, void *data,
                                    bt_self_message_iterator *self_msg_iter,
                                    const bt2c::Logger& parentLogger)
{
    struct bt_bfcr_cbs cbs = {
        .classes =
            {
                .signed_int = bfcr_signed_int_cb,
                .unsigned_int = bfcr_unsigned_int_cb,
                .floating_point = bfcr_floating_point_cb,
                .string_begin = bfcr_string_begin_cb,
                .string = bfcr_string_cb,
                .string_end = bfcr_string_end_cb,
                .compound_begin = bfcr_compound_begin_cb,
                .compound_end = bfcr_compound_end_cb,
            },
        .query =
            {
                .get_sequence_length = bfcr_get_sequence_length_cb,
                .borrow_variant_selected_field_class = bfcr_borrow_variant_selected_field_class_cb,
            },
    };

    BT_ASSERT(tc);
    BT_ASSERT(medops.request_bytes);
    BT_ASSERT(medops.borrow_stream);
    BT_ASSERT(max_request_sz > 0);

    bt2c::Logger logger {parentLogger, "PLUGIN/CTF/MSG-ITER"};
    BT_CPPLOGD_SPEC(logger,
                    "Creating CTF plugin message iterator: "
                    "trace-addr={}, max-request-size={}, "
                    "data={}, log-level={}",
                    fmt::ptr(tc), max_request_sz, fmt::ptr(data), logger.level());

    ctf_msg_iter_up msg_it {new ctf_msg_iter {std::move(logger)}};
    msg_it->self_msg_iter = self_msg_iter;
    msg_it->meta.tc = tc;
    msg_it->medium.medops = medops;
    msg_it->medium.max_request_sz = max_request_sz;
    msg_it->medium.data = data;
    msg_it->stack = stack_new(msg_it.get());
    msg_it->stored_values = g_array_new(FALSE, TRUE, sizeof(uint64_t));
    g_array_set_size(msg_it->stored_values, tc->stored_value_count);

    if (!msg_it->stack) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger, "Failed to create field stack.");
        goto error;
    }

    msg_it->bfcr = bt_bfcr_create(cbs, msg_it.get(), msg_it->logger);
    if (!msg_it->bfcr) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                     "Failed to create binary class reader (BFCR).");
        goto error;
    }

    ctf_msg_iter_reset(msg_it.get());
    BT_CPPLOGD_SPEC(msg_it->logger,
                    "Created CTF plugin message iterator: "
                    "trace-addr={}, max-request-size={}, "
                    "data={}, msg-it-addr={}, log-level={}",
                    fmt::ptr(tc), max_request_sz, fmt::ptr(data), fmt::ptr(msg_it),
                    msg_it->logger.level());
    msg_it->cur_packet_offset = 0;

end:
    return msg_it;

error:
    msg_it.reset();
    goto end;
}

void ctf_msg_iter_destroy(struct ctf_msg_iter *msg_it)
{
    BT_PACKET_PUT_REF_AND_RESET(msg_it->packet);
    BT_STREAM_PUT_REF_AND_RESET(msg_it->stream);
    release_all_dscopes(msg_it);

    BT_CPPLOGD_SPEC(msg_it->logger, "Destroying CTF plugin message iterator: addr={}",
                    fmt::ptr(msg_it));

    if (msg_it->stack) {
        BT_CPPLOGD_SPEC(msg_it->logger, "Destroying field stack.");
        stack_destroy(msg_it->stack);
    }

    if (msg_it->bfcr) {
        BT_CPPLOGD_SPEC(msg_it->logger, "Destroying BFCR: bfcr-addr={}", fmt::ptr(msg_it->bfcr));
        bt_bfcr_destroy(msg_it->bfcr);
    }

    if (msg_it->stored_values) {
        g_array_free(msg_it->stored_values, TRUE);
    }

    delete msg_it;
}

void ctf_msg_iter_deleter::operator()(ctf_msg_iter *iter) noexcept
{
    ctf_msg_iter_destroy(iter);
}

enum ctf_msg_iter_status ctf_msg_iter_get_next_message(struct ctf_msg_iter *msg_it,
                                                       const bt_message **message)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    BT_ASSERT_DBG(msg_it);
    BT_ASSERT_DBG(message);
    BT_CPPLOGD_SPEC(msg_it->logger, "Getting next message: msg-it-addr={}", fmt::ptr(msg_it));

    while (true) {
        status = handle_state(msg_it);
        if (G_UNLIKELY(status == CTF_MSG_ITER_STATUS_AGAIN)) {
            BT_CPPLOGD_SPEC(msg_it->logger, "Medium returned CTF_MSG_ITER_STATUS_AGAIN.");
            goto end;
        } else if (G_UNLIKELY(status != CTF_MSG_ITER_STATUS_OK)) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                         "Cannot handle state: msg-it-addr={}, state={}",
                                         fmt::ptr(msg_it), msg_it->state);
            goto end;
        }

        switch (msg_it->state) {
        case STATE_EMIT_MSG_EVENT:
            BT_ASSERT_DBG(msg_it->event_msg);

            /*
             * Check if we need to emit the delayed packet
             * beginning message instead of the event message.
             */
            if (G_UNLIKELY(msg_it->emit_delayed_packet_beginning_msg)) {
                *message = emit_delayed_packet_beg_msg(msg_it);
                if (!*message) {
                    status = CTF_MSG_ITER_STATUS_ERROR;
                }

                /*
                 * Don't forget to emit the event message of
                 * the event record that was just decoded.
                 */
                msg_it->state = STATE_EMIT_QUEUED_MSG_EVENT;

            } else {
                *message = msg_it->event_msg;
                msg_it->event_msg = NULL;
            }
            goto end;
        case STATE_EMIT_MSG_DISCARDED_EVENTS:
            /* create_msg_discarded_events() logs errors */
            *message = create_msg_discarded_events(msg_it);

            if (!*message) {
                status = CTF_MSG_ITER_STATUS_ERROR;
            }

            goto end;
        case STATE_EMIT_MSG_DISCARDED_PACKETS:
            /* create_msg_discarded_packets() logs errors */
            *message = create_msg_discarded_packets(msg_it);

            if (!*message) {
                status = CTF_MSG_ITER_STATUS_ERROR;
            }

            goto end;
        case STATE_EMIT_MSG_PACKET_BEGINNING:
            if (G_UNLIKELY(msg_it->meta.tc->quirks.barectf_event_before_packet)) {
                msg_it->emit_delayed_packet_beginning_msg = true;
                /*
                 * There is no message to return yet as this
                 * packet beginning message is delayed until we
                 * decode the first event message of the
                 * packet.
                 */
                break;
            } else {
                /* create_msg_packet_beginning() logs errors */
                *message = create_msg_packet_beginning(msg_it, false);
                if (!*message) {
                    status = CTF_MSG_ITER_STATUS_ERROR;
                }
            }

            goto end;
        case STATE_EMIT_MSG_PACKET_END_SINGLE:
        case STATE_EMIT_MSG_PACKET_END_MULTI:
            /* create_msg_packet_end() logs errors */
            *message = create_msg_packet_end(msg_it);

            if (!*message) {
                status = CTF_MSG_ITER_STATUS_ERROR;
            }

            goto end;
        case STATE_EMIT_MSG_STREAM_BEGINNING:
            /* create_msg_stream_beginning() logs errors */
            *message = create_msg_stream_beginning(msg_it);
            msg_it->emit_stream_beginning_message = false;
            msg_it->emit_stream_end_message = true;

            if (!*message) {
                status = CTF_MSG_ITER_STATUS_ERROR;
            }

            goto end;
        case STATE_EMIT_MSG_STREAM_END:
            /* create_msg_stream_end() logs errors */
            *message = create_msg_stream_end(msg_it);
            msg_it->emit_stream_end_message = false;

            if (!*message) {
                status = CTF_MSG_ITER_STATUS_ERROR;
            }

            goto end;
        case STATE_DONE:
            status = CTF_MSG_ITER_STATUS_EOF;
            goto end;
        default:
            /* Non-emitting state: continue */
            break;
        }
    }

end:
    return status;
}

static enum ctf_msg_iter_status decode_until_state(struct ctf_msg_iter *msg_it,
                                                   enum state target_state_1,
                                                   enum state target_state_2)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    BT_ASSERT_DBG(msg_it);

    do {
        /*
         * Check if we reached the state at which we want to stop
         * decoding.
         */
        if (msg_it->state == target_state_1 || msg_it->state == target_state_2) {
            goto end;
        }

        status = handle_state(msg_it);
        if (G_UNLIKELY(status == CTF_MSG_ITER_STATUS_AGAIN)) {
            BT_CPPLOGD_SPEC(msg_it->logger, "Medium returned CTF_MSG_ITER_STATUS_AGAIN.");
            goto end;
        } else if (G_UNLIKELY(status != CTF_MSG_ITER_STATUS_OK)) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(msg_it->logger,
                                         "Cannot handle state: msg-it-addr={}, state={}",
                                         fmt::ptr(msg_it), msg_it->state);
            goto end;
        }

        switch (msg_it->state) {
        case STATE_INIT:
        case STATE_SWITCH_PACKET:
        case STATE_DSCOPE_TRACE_PACKET_HEADER_BEGIN:
        case STATE_DSCOPE_TRACE_PACKET_HEADER_CONTINUE:
        case STATE_AFTER_TRACE_PACKET_HEADER:
        case STATE_DSCOPE_STREAM_PACKET_CONTEXT_BEGIN:
        case STATE_DSCOPE_STREAM_PACKET_CONTEXT_CONTINUE:
        case STATE_AFTER_STREAM_PACKET_CONTEXT:
        case STATE_EMIT_MSG_STREAM_BEGINNING:
        case STATE_CHECK_EMIT_MSG_DISCARDED_EVENTS:
        case STATE_EMIT_MSG_DISCARDED_EVENTS:
        case STATE_CHECK_EMIT_MSG_DISCARDED_PACKETS:
        case STATE_EMIT_MSG_DISCARDED_PACKETS:
        case STATE_EMIT_MSG_PACKET_BEGINNING:
        case STATE_DSCOPE_EVENT_HEADER_BEGIN:
        case STATE_DSCOPE_EVENT_HEADER_CONTINUE:
        case STATE_AFTER_EVENT_HEADER:
        case STATE_DSCOPE_EVENT_COMMON_CONTEXT_BEGIN:
        case STATE_DSCOPE_EVENT_COMMON_CONTEXT_CONTINUE:
        case STATE_DSCOPE_EVENT_SPEC_CONTEXT_BEGIN:
        case STATE_DSCOPE_EVENT_SPEC_CONTEXT_CONTINUE:
        case STATE_DSCOPE_EVENT_PAYLOAD_BEGIN:
        case STATE_DSCOPE_EVENT_PAYLOAD_CONTINUE:
        case STATE_EMIT_MSG_EVENT:
        case STATE_EMIT_QUEUED_MSG_EVENT:
        case STATE_SKIP_PACKET_PADDING:
        case STATE_EMIT_MSG_PACKET_END_MULTI:
        case STATE_EMIT_MSG_PACKET_END_SINGLE:
        case STATE_EMIT_QUEUED_MSG_PACKET_END:
        case STATE_EMIT_MSG_STREAM_END:
            break;
        case STATE_DONE:
            /* fall-through */
        default:
            /* We should never get to the STATE_DONE state. */
            BT_CPPLOGF_SPEC(msg_it->logger, "Unexpected state: msg-it-addr={}, state={}",
                            fmt::ptr(msg_it), msg_it->state);
            bt_common_abort();
        }
    } while (true);

end:
    return status;
}

static enum ctf_msg_iter_status read_packet_header_context_fields(struct ctf_msg_iter *msg_it)
{
    int ret;
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    status = decode_until_state(msg_it, STATE_EMIT_MSG_PACKET_BEGINNING, (state) -1);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        goto end;
    }

    ret = set_current_packet_content_sizes(msg_it);
    if (ret) {
        status = CTF_MSG_ITER_STATUS_ERROR;
        goto end;
    }

end:
    return status;
}

enum ctf_msg_iter_status ctf_msg_iter_seek(struct ctf_msg_iter *msg_it, off_t offset)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;
    enum ctf_msg_iter_medium_status medium_status;

    BT_ASSERT(msg_it);
    BT_ASSERT(offset >= 0);
    BT_ASSERT(msg_it->medium.medops.seek);

    medium_status = msg_it->medium.medops.seek(offset, msg_it->medium.data);
    if (medium_status != CTF_MSG_ITER_MEDIUM_STATUS_OK) {
        if (medium_status == CTF_MSG_ITER_MEDIUM_STATUS_EOF) {
            status = CTF_MSG_ITER_STATUS_EOF;
        } else {
            status = CTF_MSG_ITER_STATUS_ERROR;
            goto end;
        }
    }

    ctf_msg_iter_reset(msg_it);
    msg_it->cur_packet_offset = offset;

end:
    return status;
}

static enum ctf_msg_iter_status clock_snapshot_at_msg_iter_state(struct ctf_msg_iter *msg_it,
                                                                 enum state target_state_1,
                                                                 enum state target_state_2,
                                                                 uint64_t *clock_snapshot)
{
    enum ctf_msg_iter_status status = CTF_MSG_ITER_STATUS_OK;

    BT_ASSERT_DBG(msg_it);
    BT_ASSERT_DBG(clock_snapshot);
    status = decode_until_state(msg_it, target_state_1, target_state_2);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        goto end;
    }

    *clock_snapshot = msg_it->default_clock_snapshot;
end:
    return status;
}

enum ctf_msg_iter_status
ctf_msg_iter_curr_packet_first_event_clock_snapshot(struct ctf_msg_iter *msg_it,
                                                    uint64_t *first_clock_snapshot)
{
    return clock_snapshot_at_msg_iter_state(msg_it, STATE_AFTER_EVENT_HEADER, (state) -1,
                                            first_clock_snapshot);
}

enum ctf_msg_iter_status
ctf_msg_iter_curr_packet_last_event_clock_snapshot(struct ctf_msg_iter *msg_it,
                                                   uint64_t *last_clock_snapshot)
{
    return clock_snapshot_at_msg_iter_state(msg_it, STATE_EMIT_MSG_PACKET_END_SINGLE,
                                            STATE_EMIT_MSG_PACKET_END_MULTI, last_clock_snapshot);
}

enum ctf_msg_iter_status
ctf_msg_iter_get_packet_properties(struct ctf_msg_iter *msg_it,
                                   struct ctf_msg_iter_packet_properties *props)
{
    enum ctf_msg_iter_status status;

    BT_ASSERT_DBG(msg_it);
    BT_ASSERT_DBG(props);
    status = read_packet_header_context_fields(msg_it);
    if (status != CTF_MSG_ITER_STATUS_OK) {
        goto end;
    }

    props->exp_packet_total_size = msg_it->cur_exp_packet_total_size;
    props->exp_packet_content_size = msg_it->cur_exp_packet_content_size;
    props->stream_class_id = (uint64_t) msg_it->cur_stream_class_id;
    props->data_stream_id = msg_it->cur_data_stream_id;
    props->snapshots.discarded_events = msg_it->snapshots.discarded_events;
    props->snapshots.packets = msg_it->snapshots.packets;
    props->snapshots.beginning_clock = msg_it->snapshots.beginning_clock;
    props->snapshots.end_clock = msg_it->snapshots.end_clock;

end:
    return status;
}

void ctf_msg_iter_set_dry_run(struct ctf_msg_iter *msg_it, bool val)
{
    msg_it->dry_run = val;
}
