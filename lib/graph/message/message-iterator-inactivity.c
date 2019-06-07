/*
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
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

#define BT_LOG_TAG "MSG-MESSAGE-ITERATOR-INACTIVITY"
#include <babeltrace2/lib-logging-internal.h>

#include <babeltrace2/assert-pre-internal.h>
#include <babeltrace2/object-internal.h>
#include <babeltrace2/compiler-internal.h>
#include <babeltrace2/trace-ir/clock-class.h>
#include <babeltrace2/trace-ir/clock-snapshot-internal.h>
#include <babeltrace2/graph/message-internal.h>
#include <babeltrace2/graph/message-message-iterator-inactivity-const.h>
#include <babeltrace2/graph/message-message-iterator-inactivity.h>
#include <babeltrace2/graph/message-message-iterator-inactivity-internal.h>

static
void bt_message_message_iterator_inactivity_destroy(struct bt_object *obj)
{
	struct bt_message_message_iterator_inactivity *message =
			(struct bt_message_message_iterator_inactivity *) obj;

	BT_LIB_LOGD("Destroying message iterator inactivity message: %!+n",
			message);

	if (message->default_cs) {
		bt_clock_snapshot_recycle(message->default_cs);
		message->default_cs = NULL;
	}

	g_free(message);
}

struct bt_message *bt_message_message_iterator_inactivity_create(
		struct bt_self_message_iterator *self_msg_iter,
		const struct bt_clock_class *default_clock_class,
		uint64_t value_cycles)
{
	struct bt_self_component_port_input_message_iterator *msg_iter =
		(void *) self_msg_iter;
	struct bt_message_message_iterator_inactivity *message;
	struct bt_message *ret_msg = NULL;

	BT_ASSERT_PRE_NON_NULL(msg_iter, "Message iterator");
	BT_ASSERT_PRE_NON_NULL(default_clock_class, "Default clock class");
	BT_LIB_LOGD("Creating message iterator inactivity message object: "
		"%![iter-]+i, %![default-cc-]+K, value=%" PRIu64, msg_iter,
		default_clock_class, value_cycles);
	message = g_new0(struct bt_message_message_iterator_inactivity, 1);
	if (!message) {
		BT_LOGE_STR("Failed to allocate one message iterator "
				"inactivity message.");
		goto error;
	}
	bt_message_init(&message->parent,
		BT_MESSAGE_TYPE_MESSAGE_ITERATOR_INACTIVITY,
		bt_message_message_iterator_inactivity_destroy, NULL);
	ret_msg = &message->parent;
	message->default_cs = bt_clock_snapshot_create(
		(void *) default_clock_class);
	if (!message->default_cs) {
		goto error;
	}
	bt_clock_snapshot_set_raw_value(message->default_cs, value_cycles);

	BT_LIB_LOGD("Created message iterator inactivity message object: %!+n",
			ret_msg);
	goto end;

error:
	BT_OBJECT_PUT_REF_AND_RESET(ret_msg);

end:
	return (void *) ret_msg;
}

extern const struct bt_clock_snapshot *
bt_message_message_iterator_inactivity_borrow_default_clock_snapshot_const(
		const bt_message *msg)
{
	struct bt_message_message_iterator_inactivity *inactivity = (void *) msg;

	BT_ASSERT_PRE_NON_NULL(msg, "Message");
	BT_ASSERT_PRE_MSG_IS_TYPE(msg, BT_MESSAGE_TYPE_MESSAGE_ITERATOR_INACTIVITY);
	return inactivity->default_cs;
}
