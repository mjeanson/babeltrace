/*
 * Copyright 2016-2018 Philippe Proulx <pproulx@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define BT_LOG_TAG "PACKET"
#include <babeltrace2/lib-logging-internal.h>

#include <babeltrace2/assert-pre-internal.h>
#include <babeltrace2/trace-ir/field-internal.h>
#include <babeltrace2/trace-ir/packet-const.h>
#include <babeltrace2/trace-ir/packet.h>
#include <babeltrace2/trace-ir/packet-internal.h>
#include <babeltrace2/trace-ir/field-wrapper-internal.h>
#include <babeltrace2/trace-ir/trace.h>
#include <babeltrace2/trace-ir/stream-class-internal.h>
#include <babeltrace2/trace-ir/stream-class.h>
#include <babeltrace2/trace-ir/stream.h>
#include <babeltrace2/trace-ir/stream-internal.h>
#include <babeltrace2/trace-ir/trace-internal.h>
#include <babeltrace2/object-internal.h>
#include <babeltrace2/assert-internal.h>
#include <inttypes.h>

#define BT_ASSERT_PRE_PACKET_HOT(_packet) \
	BT_ASSERT_PRE_HOT((_packet), "Packet", ": %!+a", (_packet))

struct bt_stream *bt_packet_borrow_stream(struct bt_packet *packet)
{
	BT_ASSERT_PRE_NON_NULL(packet, "Packet");
	return packet->stream;
}

const struct bt_stream *bt_packet_borrow_stream_const(
		const struct bt_packet *packet)
{
	return bt_packet_borrow_stream((void *) packet);
}

struct bt_field *bt_packet_borrow_context_field(struct bt_packet *packet)
{
	BT_ASSERT_PRE_NON_NULL(packet, "Packet");
	return packet->context_field ? packet->context_field->field : NULL;
}

const struct bt_field *bt_packet_borrow_context_field_const(
		const struct bt_packet *packet)
{
	return bt_packet_borrow_context_field((void *) packet);
}

BT_HIDDEN
void _bt_packet_set_is_frozen(const struct bt_packet *packet, bool is_frozen)
{
	if (!packet) {
		return;
	}

	BT_LIB_LOGD("Setting packet's frozen state: %![packet-]+a, "
		"is-frozen=%d", packet, is_frozen);

	if (packet->context_field) {
		BT_LOGD_STR("Setting packet's context field's frozen state.");
		bt_field_set_is_frozen(packet->context_field->field,
			is_frozen);
	}

	((struct bt_packet *) packet)->frozen = is_frozen;
}

static inline
void reset_packet(struct bt_packet *packet)
{
	BT_ASSERT(packet);
	BT_LIB_LOGD("Resetting packet: %!+a", packet);
	bt_packet_set_is_frozen(packet, false);

	if (packet->context_field) {
		bt_field_set_is_frozen(packet->context_field->field, false);
		bt_field_reset(packet->context_field->field);
	}
}

static
void recycle_context_field(struct bt_field_wrapper *context_field,
		struct bt_stream_class *stream_class)
{
	BT_ASSERT(context_field);
	BT_LIB_LOGD("Recycling packet context field: "
		"addr=%p, %![sc-]+S, %![field-]+f", context_field,
		stream_class, context_field->field);
	bt_object_pool_recycle_object(&stream_class->packet_context_field_pool,
		context_field);
}

BT_HIDDEN
void bt_packet_recycle(struct bt_packet *packet)
{
	struct bt_stream *stream;

	BT_ASSERT(packet);
	BT_LIB_LOGD("Recycling packet: %!+a", packet);

	/*
	 * Those are the important ordered steps:
	 *
	 * 1. Reset the packet object (put any permanent reference it
	 *    has, unfreeze it and its fields in developer mode, etc.),
	 *    but do NOT put its stream's reference. This stream
	 *    contains the pool to which we're about to recycle this
	 *    packet object, so we must guarantee its existence thanks
	 *    to this existing reference.
	 *
	 * 2. Move the stream reference to our `stream`
	 *    variable so that we can set the packet's stream member
	 *    to NULL before recycling it. We CANNOT do this after
	 *    we put the stream reference because this bt_object_put_ref()
	 *    could destroy the stream, also destroying its
	 *    packet pool, thus also destroying our packet object (this
	 *    would result in an invalid write access).
	 *
	 * 3. Recycle the packet object.
	 *
	 * 4. Put our stream reference.
	 */
	reset_packet(packet);
	stream = packet->stream;
	BT_ASSERT(stream);
	packet->stream = NULL;
	bt_object_pool_recycle_object(&stream->packet_pool, packet);
	bt_object_put_no_null_check(&stream->base);
}

BT_HIDDEN
void bt_packet_destroy(struct bt_packet *packet)
{
	BT_LIB_LOGD("Destroying packet: %!+a", packet);

	if (packet->context_field) {
		if (packet->stream) {
			BT_LOGD_STR("Recycling packet's context field.");
			recycle_context_field(packet->context_field,
				packet->stream->class);
		} else {
			bt_field_wrapper_destroy(packet->context_field);
		}

		packet->context_field = NULL;
	}

	BT_LOGD_STR("Putting packet's stream.");
	BT_OBJECT_PUT_REF_AND_RESET(packet->stream);
	g_free(packet);
}

BT_HIDDEN
struct bt_packet *bt_packet_new(struct bt_stream *stream)
{
	struct bt_packet *packet = NULL;
	struct bt_trace_class *trace_class = NULL;

	BT_ASSERT(stream);
	BT_LIB_LOGD("Creating packet object: %![stream-]+s", stream);
	packet = g_new0(struct bt_packet, 1);
	if (!packet) {
		BT_LOGE_STR("Failed to allocate one packet object.");
		goto error;
	}

	bt_object_init_shared(&packet->base,
		(bt_object_release_func) bt_packet_recycle);
	packet->stream = stream;
	bt_object_get_no_null_check(stream);
	trace_class = bt_stream_class_borrow_trace_class_inline(stream->class);
	BT_ASSERT(trace_class);

	if (stream->class->packet_context_fc) {
		BT_LOGD_STR("Creating initial packet context field.");
		packet->context_field = bt_field_wrapper_create(
			&stream->class->packet_context_field_pool,
			stream->class->packet_context_fc);
		if (!packet->context_field) {
			BT_LOGE_STR("Cannot create packet context field wrapper.");
			goto error;
		}
	}

	BT_LIB_LOGD("Created packet object: %!+a", packet);
	goto end;

error:
	BT_OBJECT_PUT_REF_AND_RESET(packet);

end:
	return packet;
}

struct bt_packet *bt_packet_create(const struct bt_stream *c_stream)
{
	struct bt_packet *packet = NULL;
	struct bt_stream *stream = (void *) c_stream;

	BT_ASSERT_PRE_NON_NULL(stream, "Stream");
	packet = bt_object_pool_create_object(&stream->packet_pool);
	if (unlikely(!packet)) {
		BT_LIB_LOGE("Cannot allocate one packet from stream's packet pool: "
			"%![stream-]+s", stream);
		goto end;
	}

	if (likely(!packet->stream)) {
		packet->stream = stream;
		bt_object_get_no_null_check_no_parent_check(
			&packet->stream->base);
	}

end:
	return (void *) packet;
}

enum bt_packet_status bt_packet_move_context_field(struct bt_packet *packet,
		struct bt_packet_context_field *context_field)
{
	struct bt_stream_class *stream_class;
	struct bt_field_wrapper *field_wrapper = (void *) context_field;

	BT_ASSERT_PRE_NON_NULL(packet, "Packet");
	BT_ASSERT_PRE_NON_NULL(field_wrapper, "Context field");
	BT_ASSERT_PRE_HOT(packet, "Packet", ": %!+a", packet);
	stream_class = packet->stream->class;
	BT_ASSERT_PRE(stream_class->packet_context_fc,
		"Stream class has no packet context field class: %!+S",
		stream_class);
	BT_ASSERT_PRE(field_wrapper->field->class ==
		stream_class->packet_context_fc,
		"Unexpected packet context field's class: "
		"%![fc-]+F, %![expected-fc-]+F", field_wrapper->field->class,
		stream_class->packet_context_fc);

	/* Recycle current context field: always exists */
	BT_ASSERT(packet->context_field);
	recycle_context_field(packet->context_field, stream_class);

	/* Move new field */
	packet->context_field = field_wrapper;
	return BT_PACKET_STATUS_OK;
}

void bt_packet_get_ref(const struct bt_packet *packet)
{
	bt_object_get_ref(packet);
}

void bt_packet_put_ref(const struct bt_packet *packet)
{
	bt_object_put_ref(packet);
}
