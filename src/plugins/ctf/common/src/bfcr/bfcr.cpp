/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2015-2016 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2015-2016 Philippe Proulx <pproulx@efficios.com>
 *
 * Babeltrace - CTF binary field class reader (BFCR)
 */

#include "common/align.h"
#include "common/assert.h"
#include "common/common.h"
#include "compat/bitfield.h"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "../metadata/tsdl/ctf-meta.hpp"
#include "bfcr.hpp"

#define DIV8(_x)                ((_x) >> 3)
#define BYTES_TO_BITS(_x)       ((_x) *8)
#define BITS_TO_BYTES_FLOOR(_x) DIV8(_x)
#define BITS_TO_BYTES_CEIL(_x)  DIV8((_x) + 7)
#define IN_BYTE_OFFSET(_at)     ((_at) &7)

/* A visit stack entry */
struct stack_entry
{
    /*
     * Current class of base field, one of:
     *
     *   * Structure
     *   * Array
     *   * Sequence
     *   * Variant
     */
    struct ctf_field_class *base_class;

    /* Length of base field (always 1 for a variant class) */
    int64_t base_len;

    /* Index of next field to read */
    int64_t index;
};

/* Visit stack */
struct stack
{
    struct bt_bfcr *bfcr;

    /* Entries (struct stack_entry) */
    GArray *entries;

    /* Number of active entries */
    size_t size;
};

/* Reading states */
enum bfcr_state
{
    BFCR_STATE_NEXT_FIELD,
    BFCR_STATE_ALIGN_BASIC,
    BFCR_STATE_ALIGN_COMPOUND,
    BFCR_STATE_READ_BASIC_BEGIN,
    BFCR_STATE_READ_BASIC_CONTINUE,
    BFCR_STATE_DONE,
};

static const char *format_as(bfcr_state state) noexcept
{
    switch (state) {
    case BFCR_STATE_NEXT_FIELD:
        return "NEXT_FIELD";

    case BFCR_STATE_ALIGN_BASIC:
        return "ALIGN_BASIC";

    case BFCR_STATE_ALIGN_COMPOUND:
        return "ALIGN_COMPOUND";

    case BFCR_STATE_READ_BASIC_BEGIN:
        return "READ_BASIC_BEGIN";

    case BFCR_STATE_READ_BASIC_CONTINUE:
        return "READ_BASIC_CONTINUE";

    case BFCR_STATE_DONE:
        return "DONE";
    }

    bt_common_abort();
}

/* Binary class reader */
struct bt_bfcr
{
    explicit bt_bfcr(const bt2c::Logger& parentLogger) : logger {parentLogger, "PLUGIN/CTF/BFCR"}
    {
    }

    bt2c::Logger logger;

    /* BFCR stack */
    struct stack *stack = nullptr;

    /* Current basic field class */
    struct ctf_field_class *cur_basic_field_class = nullptr;

    /* Current state */
    enum bfcr_state state = static_cast<bfcr_state>(0);

    /*
     * Last basic field class's byte order.
     *
     * This is used to detect errors since two contiguous basic
     * classes for which the common boundary is not the boundary of
     * a byte cannot have different byte orders.
     *
     * This is set to CTF_BYTE_ORDER_UNKNOWN on reset and when the last
     * basic field class was a string class.
     */
    enum ctf_byte_order last_bo = CTF_BYTE_ORDER_UNKNOWN;

    /* Current byte order (copied to last_bo after a successful read) */
    enum ctf_byte_order cur_bo = CTF_BYTE_ORDER_UNKNOWN;

    /* Stitch buffer infos */
    struct
    {
        /* Stitch buffer */
        uint8_t buf[16] {};

        /* Offset, within stitch buffer, of first bit */
        size_t offset = 0;

        /* Length (bits) of data in stitch buffer from offset */
        size_t at = 0;
    } stitch;

    /* User buffer infos */
    struct
    {
        /* Address */
        const uint8_t *addr = nullptr;

        /* Offset of data from address (bits) */
        size_t offset = 0;

        /* Current position from offset (bits) */
        size_t at = 0;

        /* Offset of offset within whole packet (bits) */
        size_t packet_offset = 0;

        /* Data size in buffer (bits) */
        size_t sz = 0;

        /* Buffer size (bytes) */
        size_t buf_sz = 0;
    } buf;

    /* User stuff */
    struct
    {
        /* Callback functions */
        bt_bfcr_cbs cbs {};

        /* Private data */
        void *data = nullptr;
    } user;
};

static struct stack *stack_new(struct bt_bfcr *bfcr)
{
    struct stack *stack = NULL;

    stack = g_new0(struct stack, 1);
    if (!stack) {
        BT_CPPLOGE_SPEC(bfcr->logger, "Failed to allocate one stack.");
        goto error;
    }

    stack->bfcr = bfcr;
    stack->entries = g_array_new(FALSE, TRUE, sizeof(struct stack_entry));
    if (!stack->entries) {
        BT_CPPLOGE_SPEC(bfcr->logger, "Failed to allocate a GArray.");
        goto error;
    }

    BT_CPPLOGD_SPEC(bfcr->logger, "Created stack: addr={}", fmt::ptr(stack));
    return stack;

error:
    g_free(stack);
    return NULL;
}

static void stack_destroy(struct stack *stack)
{
    struct bt_bfcr *bfcr;

    if (!stack) {
        return;
    }

    bfcr = stack->bfcr;
    BT_CPPLOGD_SPEC(bfcr->logger, "Destroying stack: addr={}", fmt::ptr(stack));

    if (stack->entries) {
        g_array_free(stack->entries, TRUE);
    }

    g_free(stack);
}

static int stack_push(struct stack *stack, struct ctf_field_class *base_class, size_t base_len)
{
    struct stack_entry *entry;
    struct bt_bfcr *bfcr;

    BT_ASSERT_DBG(stack);
    BT_ASSERT_DBG(base_class);
    bfcr = stack->bfcr;
    BT_CPPLOGT_SPEC(bfcr->logger,
                    "Pushing field class on stack: stack-addr={}, "
                    "fc-addr={}, fc-type={}, base-length={}, "
                    "stack-size-before={}, stack-size-after={}",
                    fmt::ptr(stack), fmt::ptr(base_class), (int) base_class->type, base_len,
                    stack->size, stack->size + 1);

    if (stack->entries->len == stack->size) {
        g_array_set_size(stack->entries, stack->size + 1);
    }

    entry = &bt_g_array_index(stack->entries, struct stack_entry, stack->size);
    entry->base_class = base_class;
    entry->base_len = base_len;
    entry->index = 0;
    stack->size++;
    return 0;
}

static inline int64_t get_compound_field_class_length(struct bt_bfcr *bfcr,
                                                      struct ctf_field_class *fc)
{
    int64_t length;

    switch (fc->type) {
    case CTF_FIELD_CLASS_TYPE_STRUCT:
    {
        ctf_field_class_struct *struct_fc = ctf_field_class_as_struct(fc);

        length = (int64_t) struct_fc->members->len;
        break;
    }
    case CTF_FIELD_CLASS_TYPE_VARIANT:
    {
        /* Variant field classes always "contain" a single class */
        length = 1;
        break;
    }
    case CTF_FIELD_CLASS_TYPE_ARRAY:
    {
        struct ctf_field_class_array *array_fc = ctf_field_class_as_array(fc);

        length = (int64_t) array_fc->length;
        break;
    }
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
        length = bfcr->user.cbs.query.get_sequence_length(fc, bfcr->user.data);
        break;
    default:
        bt_common_abort();
    }

    return length;
}

static int stack_push_with_len(struct bt_bfcr *bfcr, struct ctf_field_class *base_class)
{
    int ret;
    int64_t length = get_compound_field_class_length(bfcr, base_class);

    if (length < 0) {
        BT_CPPLOGW_SPEC(bfcr->logger,
                        "Cannot get compound field class's field count: "
                        "bfcr-addr={}, fc-addr={}, fc-type={}",
                        fmt::ptr(bfcr), fmt::ptr(base_class), (int) base_class->type);
        ret = BT_BFCR_STATUS_ERROR;
        goto end;
    }

    ret = stack_push(bfcr->stack, base_class, (size_t) length);

end:
    return ret;
}

static inline unsigned int stack_size(struct stack *stack)
{
    BT_ASSERT_DBG(stack);
    return stack->size;
}

static void stack_pop(struct stack *stack)
{
    struct bt_bfcr *bfcr;

    BT_ASSERT_DBG(stack);
    BT_ASSERT_DBG(stack_size(stack));
    bfcr = stack->bfcr;
    BT_CPPLOGT_SPEC(bfcr->logger,
                    "Popping from stack: "
                    "stack-addr={}, stack-size-before={}, stack-size-after={}",
                    fmt::ptr(stack), stack->entries->len, stack->entries->len - 1);
    stack->size--;
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

static inline struct stack_entry *stack_top(struct stack *stack)
{
    BT_ASSERT_DBG(stack);
    BT_ASSERT_DBG(stack_size(stack));
    return &bt_g_array_index(stack->entries, struct stack_entry, stack->size - 1);
}

static inline size_t available_bits(struct bt_bfcr *bfcr)
{
    return bfcr->buf.sz - bfcr->buf.at;
}

static inline void consume_bits(struct bt_bfcr *bfcr, size_t incr)
{
    BT_CPPLOGT_SPEC(bfcr->logger, "Advancing cursor: bfcr-addr={}, cur-before={}, cur-after={}",
                    fmt::ptr(bfcr), bfcr->buf.at, bfcr->buf.at + incr);
    bfcr->buf.at += incr;
}

static inline bool has_enough_bits(struct bt_bfcr *bfcr, size_t sz)
{
    return available_bits(bfcr) >= sz;
}

static inline bool at_least_one_bit_left(struct bt_bfcr *bfcr)
{
    return has_enough_bits(bfcr, 1);
}

static inline size_t packet_at(struct bt_bfcr *bfcr)
{
    return bfcr->buf.packet_offset + bfcr->buf.at;
}

static inline size_t buf_at_from_addr(struct bt_bfcr *bfcr)
{
    /*
     * Considering this:
     *
     *     ====== offset ===== (17)
     *
     *     xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
     *     ^
     *     addr (0)           ==== at ==== (12)
     *
     * We want this:
     *
     *     =============================== (29)
     */
    return bfcr->buf.offset + bfcr->buf.at;
}

static void stitch_reset(struct bt_bfcr *bfcr)
{
    bfcr->stitch.offset = 0;
    bfcr->stitch.at = 0;
}

static inline size_t stitch_at_from_addr(struct bt_bfcr *bfcr)
{
    return bfcr->stitch.offset + bfcr->stitch.at;
}

static void stitch_append_from_buf(struct bt_bfcr *bfcr, size_t sz)
{
    size_t stitch_byte_at;
    size_t buf_byte_at;
    size_t nb_bytes;

    if (sz == 0) {
        return;
    }

    stitch_byte_at = BITS_TO_BYTES_FLOOR(stitch_at_from_addr(bfcr));
    buf_byte_at = BITS_TO_BYTES_FLOOR(buf_at_from_addr(bfcr));
    nb_bytes = BITS_TO_BYTES_CEIL(sz);
    BT_ASSERT(nb_bytes > 0);
    BT_ASSERT(bfcr->buf.addr);
    memcpy(&bfcr->stitch.buf[stitch_byte_at], &bfcr->buf.addr[buf_byte_at], nb_bytes);
    bfcr->stitch.at += sz;
    consume_bits(bfcr, sz);
}

static void stitch_append_from_remaining_buf(struct bt_bfcr *bfcr)
{
    stitch_append_from_buf(bfcr, available_bits(bfcr));
}

static void stitch_set_from_remaining_buf(struct bt_bfcr *bfcr)
{
    stitch_reset(bfcr);
    bfcr->stitch.offset = IN_BYTE_OFFSET(buf_at_from_addr(bfcr));
    stitch_append_from_remaining_buf(bfcr);
}

static inline void read_unsigned_bitfield(struct bt_bfcr *bfcr, const uint8_t *buf, size_t at,
                                          unsigned int field_size, enum ctf_byte_order bo,
                                          uint64_t *v)
{
    switch (bo) {
    case CTF_BYTE_ORDER_BIG:
        bt_bitfield_read_be(buf, uint8_t, at, field_size, v);
        break;
    case CTF_BYTE_ORDER_LITTLE:
        bt_bitfield_read_le(buf, uint8_t, at, field_size, v);
        break;
    default:
        bt_common_abort();
    }

    BT_CPPLOGT_SPEC(bfcr->logger, "Read unsigned bit array: cur={}, size={}, bo={}, val={}", at,
                    field_size, (int) bo, *v);
}

static inline void read_signed_bitfield(struct bt_bfcr *bfcr, const uint8_t *buf, size_t at,
                                        unsigned int field_size, enum ctf_byte_order bo, int64_t *v)
{
    switch (bo) {
    case CTF_BYTE_ORDER_BIG:
        bt_bitfield_read_be(buf, uint8_t, at, field_size, v);
        break;
    case CTF_BYTE_ORDER_LITTLE:
        bt_bitfield_read_le(buf, uint8_t, at, field_size, v);
        break;
    default:
        bt_common_abort();
    }

    BT_CPPLOGT_SPEC(bfcr->logger, "Read signed bit array: cur={}, size={}, bo={}, val={}", at,
                    field_size, (int) bo, *v);
}

typedef enum bt_bfcr_status (*read_basic_and_call_cb_t)(struct bt_bfcr *, const uint8_t *, size_t);

static inline enum bt_bfcr_status validate_contiguous_bo(struct bt_bfcr *bfcr,
                                                         enum ctf_byte_order next_bo)
{
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;

    /* Always valid when at a byte boundary */
    if (packet_at(bfcr) % 8 == 0) {
        goto end;
    }

    /* Always valid if last byte order is unknown */
    if (bfcr->last_bo == CTF_BYTE_ORDER_UNKNOWN) {
        goto end;
    }

    /* Always valid if next byte order is unknown */
    if (next_bo == CTF_BYTE_ORDER_UNKNOWN) {
        goto end;
    }

    /* Make sure last byte order is compatible with the next byte order */
    switch (bfcr->last_bo) {
    case CTF_BYTE_ORDER_BIG:
        if (next_bo != CTF_BYTE_ORDER_BIG) {
            status = BT_BFCR_STATUS_ERROR;
        }
        break;
    case CTF_BYTE_ORDER_LITTLE:
        if (next_bo != CTF_BYTE_ORDER_LITTLE) {
            status = BT_BFCR_STATUS_ERROR;
        }
        break;
    default:
        status = BT_BFCR_STATUS_ERROR;
    }

end:
    if (status < 0) {
        BT_CPPLOGW_SPEC(bfcr->logger,
                        "Cannot read bit array: two different byte orders not at a byte boundary: "
                        "bfcr-addr={}, last-bo={}, next-bo={}",
                        fmt::ptr(bfcr), (int) bfcr->last_bo, (int) next_bo);
    }

    return status;
}

static enum bt_bfcr_status read_basic_float_and_call_cb(struct bt_bfcr *bfcr, const uint8_t *buf,
                                                        size_t at)
{
    double dblval;
    unsigned int field_size;
    enum ctf_byte_order bo;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    ctf_field_class_float *fc = ctf_field_class_as_float(bfcr->cur_basic_field_class);

    BT_ASSERT_DBG(fc);
    field_size = fc->base.size;
    bo = fc->base.byte_order;
    bfcr->cur_bo = bo;

    switch (field_size) {
    case 32:
    {
        uint64_t v;
        union
        {
            uint32_t u;
            float f;
        } f32;

        read_unsigned_bitfield(bfcr, buf, at, field_size, bo, &v);
        f32.u = (uint32_t) v;
        dblval = (double) f32.f;
        break;
    }
    case 64:
    {
        union
        {
            uint64_t u;
            double d;
        } f64;

        read_unsigned_bitfield(bfcr, buf, at, field_size, bo, &f64.u);
        dblval = f64.d;
        break;
    }
    default:
        /* Only 32-bit and 64-bit fields are supported currently */
        bt_common_abort();
    }

    BT_CPPLOGT_SPEC(bfcr->logger, "Read floating point number value: bfcr={}, cur={}, val={}",
                    fmt::ptr(bfcr), at, dblval);

    if (bfcr->user.cbs.classes.floating_point) {
        BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (floating point number).");
        status = bfcr->user.cbs.classes.floating_point(dblval, bfcr->cur_basic_field_class,
                                                       bfcr->user.data);
        BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
        if (status != BT_BFCR_STATUS_OK) {
            BT_CPPLOGW_SPEC(bfcr->logger, "User function failed: bfcr-addr={}, status={}",
                            fmt::ptr(bfcr), status);
        }
    }

    return status;
}

static inline enum bt_bfcr_status read_basic_int_and_call_cb(struct bt_bfcr *bfcr,
                                                             const uint8_t *buf, size_t at)
{
    unsigned int field_size;
    enum ctf_byte_order bo;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    ctf_field_class_int *fc = ctf_field_class_as_int(bfcr->cur_basic_field_class);

    field_size = fc->base.size;
    bo = fc->base.byte_order;

    /*
     * Update current byte order now because we could be reading
     * the integer value of an enumeration class, and thus we know
     * here the actual supporting integer class's byte order.
     */
    bfcr->cur_bo = bo;

    if (fc->is_signed) {
        int64_t v;

        read_signed_bitfield(bfcr, buf, at, field_size, bo, &v);

        if (bfcr->user.cbs.classes.signed_int) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (signed integer).");
            status =
                bfcr->user.cbs.classes.signed_int(v, bfcr->cur_basic_field_class, bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
            if (status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger,
                                "User function failed: "
                                "bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), status);
            }
        }
    } else {
        uint64_t v;

        read_unsigned_bitfield(bfcr, buf, at, field_size, bo, &v);

        if (bfcr->user.cbs.classes.unsigned_int) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (unsigned integer).");
            status = bfcr->user.cbs.classes.unsigned_int(v, bfcr->cur_basic_field_class,
                                                         bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
            if (status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger,
                                "User function failed: "
                                "bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), status);
            }
        }
    }

    return status;
}

static inline enum bt_bfcr_status
read_bit_array_class_and_call_continue(struct bt_bfcr *bfcr,
                                       read_basic_and_call_cb_t read_basic_and_call_cb)
{
    size_t available;
    size_t needed_bits;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    ctf_field_class_bit_array *fc = ctf_field_class_as_bit_array(bfcr->cur_basic_field_class);

    if (!at_least_one_bit_left(bfcr)) {
        BT_CPPLOGT_SPEC(bfcr->logger, "Reached end of data: bfcr-addr={}", fmt::ptr(bfcr));
        status = BT_BFCR_STATUS_EOF;
        goto end;
    }

    available = available_bits(bfcr);
    needed_bits = fc->size - bfcr->stitch.at;
    BT_CPPLOGT_SPEC(bfcr->logger,
                    "Continuing basic field decoding: "
                    "bfcr-addr={}, field-size={}, needed-size={}, "
                    "available-size={}",
                    fmt::ptr(bfcr), fc->size, needed_bits, available);
    if (needed_bits <= available) {
        /* We have all the bits; append to stitch, then decode */
        stitch_append_from_buf(bfcr, needed_bits);
        status = read_basic_and_call_cb(bfcr, bfcr->stitch.buf, bfcr->stitch.offset);
        if (status != BT_BFCR_STATUS_OK) {
            BT_CPPLOGW_SPEC(bfcr->logger,
                            "Cannot read basic field: "
                            "bfcr-addr={}, fc-addr={}, status={}",
                            fmt::ptr(bfcr), fmt::ptr(bfcr->cur_basic_field_class), status);
            goto end;
        }

        if (stack_empty(bfcr->stack)) {
            /* Root is a basic class */
            bfcr->state = BFCR_STATE_DONE;
        } else {
            /* Go to next field */
            stack_top(bfcr->stack)->index++;
            bfcr->state = BFCR_STATE_NEXT_FIELD;
            bfcr->last_bo = bfcr->cur_bo;
        }
        goto end;
    }

    /* We are here; it means we don't have enough data to decode this */
    BT_CPPLOGT_SPEC(bfcr->logger,
                    "Not enough data to read the next basic field: appending to stitch buffer.");
    stitch_append_from_remaining_buf(bfcr);
    status = BT_BFCR_STATUS_EOF;

end:
    return status;
}

static inline enum bt_bfcr_status
read_bit_array_class_and_call_begin(struct bt_bfcr *bfcr,
                                    read_basic_and_call_cb_t read_basic_and_call_cb)
{
    size_t available;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;
    ctf_field_class_bit_array *fc = ctf_field_class_as_bit_array(bfcr->cur_basic_field_class);

    if (!at_least_one_bit_left(bfcr)) {
        BT_CPPLOGT_SPEC(bfcr->logger, "Reached end of data: bfcr-addr={}", fmt::ptr(bfcr));
        status = BT_BFCR_STATUS_EOF;
        goto end;
    }

    status = validate_contiguous_bo(bfcr, fc->byte_order);
    if (status != BT_BFCR_STATUS_OK) {
        /* validate_contiguous_bo() logs errors */
        goto end;
    }

    available = available_bits(bfcr);

    if (fc->size <= available) {
        /* We have all the bits; decode and set now */
        BT_ASSERT_DBG(bfcr->buf.addr);
        status = read_basic_and_call_cb(bfcr, bfcr->buf.addr, buf_at_from_addr(bfcr));
        if (status != BT_BFCR_STATUS_OK) {
            BT_CPPLOGW_SPEC(bfcr->logger,
                            "Cannot read basic field: "
                            "bfcr-addr={}, fc-addr={}, status={}",
                            fmt::ptr(bfcr), fmt::ptr(bfcr->cur_basic_field_class), status);
            goto end;
        }

        consume_bits(bfcr, fc->size);

        if (stack_empty(bfcr->stack)) {
            /* Root is a basic class */
            bfcr->state = BFCR_STATE_DONE;
        } else {
            /* Go to next field */
            stack_top(bfcr->stack)->index++;
            bfcr->state = BFCR_STATE_NEXT_FIELD;
            bfcr->last_bo = bfcr->cur_bo;
        }

        goto end;
    }

    /* We are here; it means we don't have enough data to decode this */
    BT_CPPLOGT_SPEC(bfcr->logger,
                    "Not enough data to read the next basic field: setting stitch buffer.");
    stitch_set_from_remaining_buf(bfcr);
    bfcr->state = BFCR_STATE_READ_BASIC_CONTINUE;
    status = BT_BFCR_STATUS_EOF;

end:
    return status;
}

static inline enum bt_bfcr_status read_basic_int_class_and_call_begin(struct bt_bfcr *bfcr)
{
    return read_bit_array_class_and_call_begin(bfcr, read_basic_int_and_call_cb);
}

static inline enum bt_bfcr_status read_basic_int_class_and_call_continue(struct bt_bfcr *bfcr)
{
    return read_bit_array_class_and_call_continue(bfcr, read_basic_int_and_call_cb);
}

static inline enum bt_bfcr_status read_basic_float_class_and_call_begin(struct bt_bfcr *bfcr)
{
    return read_bit_array_class_and_call_begin(bfcr, read_basic_float_and_call_cb);
}

static inline enum bt_bfcr_status read_basic_float_class_and_call_continue(struct bt_bfcr *bfcr)
{
    return read_bit_array_class_and_call_continue(bfcr, read_basic_float_and_call_cb);
}

static inline enum bt_bfcr_status read_basic_string_class_and_call(struct bt_bfcr *bfcr, bool begin)
{
    size_t buf_at_bytes;
    const uint8_t *result;
    size_t available_bytes;
    const uint8_t *first_chr;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;

    if (!at_least_one_bit_left(bfcr)) {
        BT_CPPLOGT_SPEC(bfcr->logger, "Reached end of data: bfcr-addr={}", fmt::ptr(bfcr));
        status = BT_BFCR_STATUS_EOF;
        goto end;
    }

    BT_ASSERT_DBG(buf_at_from_addr(bfcr) % 8 == 0);
    available_bytes = BITS_TO_BYTES_FLOOR(available_bits(bfcr));
    buf_at_bytes = BITS_TO_BYTES_FLOOR(buf_at_from_addr(bfcr));
    BT_ASSERT_DBG(bfcr->buf.addr);
    first_chr = &bfcr->buf.addr[buf_at_bytes];
    result = (const uint8_t *) memchr(first_chr, '\0', available_bytes);

    if (begin && bfcr->user.cbs.classes.string_begin) {
        BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (string, beginning).");
        status = bfcr->user.cbs.classes.string_begin(bfcr->cur_basic_field_class, bfcr->user.data);
        BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
        if (status != BT_BFCR_STATUS_OK) {
            BT_CPPLOGW_SPEC(bfcr->logger, "User function failed: bfcr-addr={}, status={}",
                            fmt::ptr(bfcr), status);
            goto end;
        }
    }

    if (!result) {
        /* No null character yet */
        if (bfcr->user.cbs.classes.string) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (substring).");
            status = bfcr->user.cbs.classes.string((const char *) first_chr, available_bytes,
                                                   bfcr->cur_basic_field_class, bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
            if (status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger,
                                "User function failed: "
                                "bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), status);
                goto end;
            }
        }

        consume_bits(bfcr, BYTES_TO_BITS(available_bytes));
        bfcr->state = BFCR_STATE_READ_BASIC_CONTINUE;
        status = BT_BFCR_STATUS_EOF;
    } else {
        /* Found the null character */
        size_t result_len = (size_t) (result - first_chr);

        if (bfcr->user.cbs.classes.string && result_len) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (substring).");
            status = bfcr->user.cbs.classes.string((const char *) first_chr, result_len,
                                                   bfcr->cur_basic_field_class, bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
            if (status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger,
                                "User function failed: "
                                "bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), status);
                goto end;
            }
        }

        if (bfcr->user.cbs.classes.string_end) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (string, end).");
            status =
                bfcr->user.cbs.classes.string_end(bfcr->cur_basic_field_class, bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
            if (status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger,
                                "User function failed: "
                                "bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), status);
                goto end;
            }
        }

        consume_bits(bfcr, BYTES_TO_BITS(result_len + 1));

        if (stack_empty(bfcr->stack)) {
            /* Root is a basic class */
            bfcr->state = BFCR_STATE_DONE;
        } else {
            /* Go to next field */
            stack_top(bfcr->stack)->index++;
            bfcr->state = BFCR_STATE_NEXT_FIELD;
            bfcr->last_bo = bfcr->cur_bo;
        }
    }

end:
    return status;
}

static inline enum bt_bfcr_status read_basic_begin_state(struct bt_bfcr *bfcr)
{
    enum bt_bfcr_status status;

    BT_ASSERT_DBG(bfcr->cur_basic_field_class);

    switch (bfcr->cur_basic_field_class->type) {
    case CTF_FIELD_CLASS_TYPE_INT:
    case CTF_FIELD_CLASS_TYPE_ENUM:
        status = read_basic_int_class_and_call_begin(bfcr);
        break;
    case CTF_FIELD_CLASS_TYPE_FLOAT:
        status = read_basic_float_class_and_call_begin(bfcr);
        break;
    case CTF_FIELD_CLASS_TYPE_STRING:
        status = read_basic_string_class_and_call(bfcr, true);
        break;
    default:
        bt_common_abort();
    }

    return status;
}

static inline enum bt_bfcr_status read_basic_continue_state(struct bt_bfcr *bfcr)
{
    enum bt_bfcr_status status;

    BT_ASSERT_DBG(bfcr->cur_basic_field_class);

    switch (bfcr->cur_basic_field_class->type) {
    case CTF_FIELD_CLASS_TYPE_INT:
    case CTF_FIELD_CLASS_TYPE_ENUM:
        status = read_basic_int_class_and_call_continue(bfcr);
        break;
    case CTF_FIELD_CLASS_TYPE_FLOAT:
        status = read_basic_float_class_and_call_continue(bfcr);
        break;
    case CTF_FIELD_CLASS_TYPE_STRING:
        status = read_basic_string_class_and_call(bfcr, false);
        break;
    default:
        bt_common_abort();
    }

    return status;
}

static inline size_t bits_to_skip_to_align_to(struct bt_bfcr *bfcr, size_t align)
{
    size_t aligned_packet_at;

    aligned_packet_at = BT_ALIGN(packet_at(bfcr), align);
    return aligned_packet_at - packet_at(bfcr);
}

static inline enum bt_bfcr_status align_class_state(struct bt_bfcr *bfcr,
                                                    struct ctf_field_class *field_class,
                                                    enum bfcr_state next_state)
{
    unsigned int field_alignment;
    size_t skip_bits;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;

    /* Get field's alignment */
    field_alignment = field_class->alignment;

    /*
     * 0 means "undefined" for variants; what we really want is 1
     * (always aligned)
     */
    BT_ASSERT_DBG(field_alignment >= 1);

    /* Compute how many bits we need to skip */
    skip_bits = bits_to_skip_to_align_to(bfcr, (size_t) field_alignment);

    /* Nothing to skip? aligned */
    if (skip_bits == 0) {
        bfcr->state = next_state;
        goto end;
    }

    /* Make sure there's at least one bit left */
    if (!at_least_one_bit_left(bfcr)) {
        status = BT_BFCR_STATUS_EOF;
        goto end;
    }

    /* Consume as many bits as possible in what's left */
    consume_bits(bfcr, MIN(available_bits(bfcr), skip_bits));

    /* Are we done now? */
    skip_bits = bits_to_skip_to_align_to(bfcr, field_alignment);
    if (skip_bits == 0) {
        /* Yes: go to next state */
        bfcr->state = next_state;
        goto end;
    } else {
        /* No: need more data */
        BT_CPPLOGT_SPEC(bfcr->logger, "Reached end of data when aligning: bfcr-addr={}",
                        fmt::ptr(bfcr));
        status = BT_BFCR_STATUS_EOF;
    }

end:
    return status;
}

static inline enum bt_bfcr_status next_field_state(struct bt_bfcr *bfcr)
{
    int ret;
    struct stack_entry *top;
    struct ctf_field_class *next_field_class = NULL;
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;

    if (stack_empty(bfcr->stack)) {
        goto end;
    }

    top = stack_top(bfcr->stack);

    /* Are we done with this base class? */
    while (top->index == top->base_len) {
        if (bfcr->user.cbs.classes.compound_end) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (compound, end).");
            status = bfcr->user.cbs.classes.compound_end(top->base_class, bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
            if (status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger, "User function failed: bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), status);
                goto end;
            }
        }

        stack_pop(bfcr->stack);

        /* Are we done with the root class? */
        if (stack_empty(bfcr->stack)) {
            bfcr->state = BFCR_STATE_DONE;
            goto end;
        }

        top = stack_top(bfcr->stack);
        top->index++;
    }

    /* Get next field's class */
    switch (top->base_class->type) {
    case CTF_FIELD_CLASS_TYPE_STRUCT:
        next_field_class = ctf_field_class_struct_borrow_member_by_index(
                               ctf_field_class_as_struct(top->base_class), (uint64_t) top->index)
                               ->fc;
        break;
    case CTF_FIELD_CLASS_TYPE_ARRAY:
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    {
        ctf_field_class_array_base *array_fc = ctf_field_class_as_array_base(top->base_class);

        next_field_class = array_fc->elem_fc;
        break;
    }
    case CTF_FIELD_CLASS_TYPE_VARIANT:
        /* Variant classes are dynamic: the user should know! */
        next_field_class = bfcr->user.cbs.query.borrow_variant_selected_field_class(
            top->base_class, bfcr->user.data);
        break;
    default:
        break;
    }

    if (!next_field_class) {
        BT_CPPLOGW_SPEC(bfcr->logger,
                        "Cannot get the field class of the next field: "
                        "bfcr-addr={}, base-fc-addr={}, base-fc-type={}, index={}",
                        fmt::ptr(bfcr), fmt::ptr(top->base_class), (int) top->base_class->type,
                        top->index);
        status = BT_BFCR_STATUS_ERROR;
        goto end;
    }

    if (next_field_class->is_compound) {
        if (bfcr->user.cbs.classes.compound_begin) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (compound, begin).");
            status = bfcr->user.cbs.classes.compound_begin(next_field_class, bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", status);
            if (status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger, "User function failed: bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), status);
                goto end;
            }
        }

        ret = stack_push_with_len(bfcr, next_field_class);
        if (ret) {
            /* stack_push_with_len() logs errors */
            status = BT_BFCR_STATUS_ERROR;
            goto end;
        }

        /* Next state: align a compound class */
        bfcr->state = BFCR_STATE_ALIGN_COMPOUND;
    } else {
        /* Replace current basic field class */
        BT_CPPLOGT_SPEC(bfcr->logger,
                        "Replacing current basic field class: "
                        "bfcr-addr={}, cur-basic-fc-addr={}, "
                        "next-basic-fc-addr={}",
                        fmt::ptr(bfcr), fmt::ptr(bfcr->cur_basic_field_class),
                        fmt::ptr(next_field_class));
        bfcr->cur_basic_field_class = next_field_class;

        /* Next state: align a basic class */
        bfcr->state = BFCR_STATE_ALIGN_BASIC;
    }

end:
    return status;
}

static inline enum bt_bfcr_status handle_state(struct bt_bfcr *bfcr)
{
    enum bt_bfcr_status status = BT_BFCR_STATUS_OK;

    BT_CPPLOGT_SPEC(bfcr->logger, "Handling state: bfcr-addr={}, state={}", fmt::ptr(bfcr),
                    bfcr->state);

    switch (bfcr->state) {
    case BFCR_STATE_NEXT_FIELD:
        status = next_field_state(bfcr);
        break;
    case BFCR_STATE_ALIGN_BASIC:
        status = align_class_state(bfcr, bfcr->cur_basic_field_class, BFCR_STATE_READ_BASIC_BEGIN);
        break;
    case BFCR_STATE_ALIGN_COMPOUND:
        status = align_class_state(bfcr, stack_top(bfcr->stack)->base_class, BFCR_STATE_NEXT_FIELD);
        break;
    case BFCR_STATE_READ_BASIC_BEGIN:
        status = read_basic_begin_state(bfcr);
        break;
    case BFCR_STATE_READ_BASIC_CONTINUE:
        status = read_basic_continue_state(bfcr);
        break;
    case BFCR_STATE_DONE:
        break;
    }

    BT_CPPLOGT_SPEC(bfcr->logger, "Handled state: bfcr-addr={}, status={}", fmt::ptr(bfcr), status);
    return status;
}

struct bt_bfcr *bt_bfcr_create(struct bt_bfcr_cbs cbs, void *data, const bt2c::Logger& logger)
{
    BT_CPPLOGD_SPEC(logger, "Creating binary field class reader (BFCR).");

    bt_bfcr *bfcr = new bt_bfcr {logger};
    bfcr->stack = stack_new(bfcr);
    if (!bfcr->stack) {
        BT_CPPLOGE_SPEC(bfcr->logger, "Cannot create BFCR's stack.");
        bt_bfcr_destroy(bfcr);
        bfcr = NULL;
        goto end;
    }

    bfcr->state = BFCR_STATE_NEXT_FIELD;
    bfcr->user.cbs = cbs;
    bfcr->user.data = data;
    BT_CPPLOGD_SPEC(bfcr->logger, "Created BFCR: addr={}", fmt::ptr(bfcr));

end:
    return bfcr;
}

void bt_bfcr_destroy(struct bt_bfcr *bfcr)
{
    if (bfcr->stack) {
        stack_destroy(bfcr->stack);
    }

    BT_CPPLOGD_SPEC(bfcr->logger, "Destroying BFCR: addr={}", fmt::ptr(bfcr));
    delete bfcr;
}

static void reset(struct bt_bfcr *bfcr)
{
    BT_CPPLOGD_SPEC(bfcr->logger, "Resetting BFCR: addr={}", fmt::ptr(bfcr));
    stack_clear(bfcr->stack);
    stitch_reset(bfcr);
    bfcr->buf.addr = NULL;
    bfcr->last_bo = CTF_BYTE_ORDER_UNKNOWN;
}

static void update_packet_offset(struct bt_bfcr *bfcr)
{
    BT_CPPLOGT_SPEC(bfcr->logger,
                    "Updating packet offset for next call: "
                    "bfcr-addr={}, cur-packet-offset={}, next-packet-offset={}",
                    fmt::ptr(bfcr), bfcr->buf.packet_offset,
                    bfcr->buf.packet_offset + bfcr->buf.at);
    bfcr->buf.packet_offset += bfcr->buf.at;
}

size_t bt_bfcr_start(struct bt_bfcr *bfcr, struct ctf_field_class *cls, const uint8_t *buf,
                     size_t offset, size_t packet_offset, size_t sz, enum bt_bfcr_status *status)
{
    BT_ASSERT_DBG(bfcr);
    BT_ASSERT_DBG(BYTES_TO_BITS(sz) >= offset);
    reset(bfcr);
    bfcr->buf.addr = buf;
    bfcr->buf.offset = offset;
    bfcr->buf.at = 0;
    bfcr->buf.packet_offset = packet_offset;
    bfcr->buf.buf_sz = sz;
    bfcr->buf.sz = BYTES_TO_BITS(sz) - offset;
    *status = BT_BFCR_STATUS_OK;

    BT_CPPLOGT_SPEC(bfcr->logger,
                    "Starting decoding: bfcr-addr={}, fc-addr={}, "
                    "buf-addr={}, buf-size={}, offset={}, "
                    "packet-offset={}",
                    fmt::ptr(bfcr), fmt::ptr(cls), fmt::ptr(buf), sz, offset, packet_offset);

    /* Set root class */
    if (cls->is_compound) {
        /* Compound class: push on visit stack */
        int stack_ret;

        if (bfcr->user.cbs.classes.compound_begin) {
            BT_CPPLOGT_SPEC(bfcr->logger, "Calling user function (compound, begin).");
            *status = bfcr->user.cbs.classes.compound_begin(cls, bfcr->user.data);
            BT_CPPLOGT_SPEC(bfcr->logger, "User function returned: status={}", *status);
            if (*status != BT_BFCR_STATUS_OK) {
                BT_CPPLOGW_SPEC(bfcr->logger, "User function failed: bfcr-addr={}, status={}",
                                fmt::ptr(bfcr), *status);
                goto end;
            }
        }

        stack_ret = stack_push_with_len(bfcr, cls);
        if (stack_ret) {
            /* stack_push_with_len() logs errors */
            *status = BT_BFCR_STATUS_ERROR;
            goto end;
        }

        bfcr->state = BFCR_STATE_ALIGN_COMPOUND;
    } else {
        /* Basic class: set as current basic class */
        bfcr->cur_basic_field_class = cls;
        bfcr->state = BFCR_STATE_ALIGN_BASIC;
    }

    /* Run the machine! */
    BT_CPPLOGT_SPEC(bfcr->logger, "Running the state machine.");

    while (true) {
        *status = handle_state(bfcr);
        if (*status != BT_BFCR_STATUS_OK || bfcr->state == BFCR_STATE_DONE) {
            break;
        }
    }

    /* Update packet offset for next time */
    update_packet_offset(bfcr);

end:
    return bfcr->buf.at;
}

size_t bt_bfcr_continue(struct bt_bfcr *bfcr, const uint8_t *buf, size_t sz,
                        enum bt_bfcr_status *status)
{
    BT_ASSERT_DBG(bfcr);
    BT_ASSERT_DBG(buf);
    BT_ASSERT_DBG(sz > 0);
    bfcr->buf.addr = buf;
    bfcr->buf.offset = 0;
    bfcr->buf.at = 0;
    bfcr->buf.buf_sz = sz;
    bfcr->buf.sz = BYTES_TO_BITS(sz);
    *status = BT_BFCR_STATUS_OK;

    BT_CPPLOGT_SPEC(bfcr->logger, "Continuing decoding: bfcr-addr={}, buf-addr={}, buf-size={}",
                    fmt::ptr(bfcr), fmt::ptr(buf), sz);

    /* Continue running the machine */
    BT_CPPLOGT_SPEC(bfcr->logger, "Running the state machine.");

    while (true) {
        *status = handle_state(bfcr);
        if (*status != BT_BFCR_STATUS_OK || bfcr->state == BFCR_STATE_DONE) {
            break;
        }
    }

    /* Update packet offset for next time */
    update_packet_offset(bfcr);
    return bfcr->buf.at;
}

void bt_bfcr_set_unsigned_int_cb(struct bt_bfcr *bfcr, bt_bfcr_unsigned_int_cb_func cb)
{
    BT_ASSERT_DBG(bfcr);
    BT_ASSERT_DBG(cb);
    bfcr->user.cbs.classes.unsigned_int = cb;
}
