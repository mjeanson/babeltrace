/*
 * Copyright 2017 Philippe Proulx <pproulx@efficios.com>
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

#include <babeltrace2/babeltrace.h>
#include "common/macros.h"
#include "common/assert.h"
#include "dummy.h"

static
const char * const in_port_name = "in";

void destroy_private_dummy_data(struct dummy *dummy)
{
	bt_self_component_port_input_message_iterator_put_ref(dummy->msg_iter);
	g_free(dummy);

}

BT_HIDDEN
void dummy_finalize(bt_self_component_sink *comp)
{
	struct dummy *dummy;

	BT_ASSERT(comp);
	dummy = bt_self_component_get_data(
			bt_self_component_sink_as_self_component(comp));
	BT_ASSERT(dummy);
	destroy_private_dummy_data(dummy);
}

BT_HIDDEN
bt_component_class_init_method_status dummy_init(
		bt_self_component_sink *component,
		bt_self_component_sink_configuration *config,
		const bt_value *params,
		__attribute__((unused)) void *init_method_data)
{
	bt_component_class_init_method_status status =
		BT_COMPONENT_CLASS_INIT_METHOD_STATUS_OK;
	bt_self_component_add_port_status add_port_status;
	struct dummy *dummy = g_new0(struct dummy, 1);

	if (!dummy) {
		status = BT_COMPONENT_CLASS_INIT_METHOD_STATUS_MEMORY_ERROR;
		goto end;
	}

	add_port_status = bt_self_component_sink_add_input_port(component,
		"in", NULL, NULL);
	switch (add_port_status) {
	case BT_SELF_COMPONENT_ADD_PORT_STATUS_ERROR:
		status = BT_COMPONENT_CLASS_INIT_METHOD_STATUS_ERROR;
		goto error;
	case BT_SELF_COMPONENT_ADD_PORT_STATUS_MEMORY_ERROR:
		status = BT_COMPONENT_CLASS_INIT_METHOD_STATUS_MEMORY_ERROR;
		goto error;
	default:
		break;
	}

	bt_self_component_set_data(
		bt_self_component_sink_as_self_component(component), dummy);
	goto end;

error:
	destroy_private_dummy_data(dummy);

end:
	return status;
}

BT_HIDDEN
bt_component_class_sink_graph_is_configured_method_status dummy_graph_is_configured(
		bt_self_component_sink *comp)
{
	bt_component_class_sink_graph_is_configured_method_status status;
	bt_self_component_port_input_message_iterator_create_from_sink_component_status
		msg_iter_status;
	struct dummy *dummy;
	bt_self_component_port_input_message_iterator *iterator;

	dummy = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(comp));
	BT_ASSERT(dummy);
	msg_iter_status = bt_self_component_port_input_message_iterator_create_from_sink_component(
		comp, bt_self_component_sink_borrow_input_port_by_name(comp,
			in_port_name), &iterator);
	if (msg_iter_status != BT_SELF_COMPONENT_PORT_INPUT_MESSAGE_ITERATOR_CREATE_FROM_SINK_COMPONENT_STATUS_OK) {
		status = (int) msg_iter_status;
		goto end;
	}

	BT_SELF_COMPONENT_PORT_INPUT_MESSAGE_ITERATOR_MOVE_REF(
		dummy->msg_iter, iterator);

	status = BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_OK;

end:
	return status;
}

BT_HIDDEN
bt_component_class_sink_consume_method_status dummy_consume(
		bt_self_component_sink *component)
{
	bt_component_class_sink_consume_method_status status =
		BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
	bt_message_array_const msgs;
	uint64_t count;
	struct dummy *dummy;
	bt_message_iterator_next_status next_status;
	uint64_t i;

	dummy = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(component));
	BT_ASSERT(dummy);

	if (G_UNLIKELY(!dummy->msg_iter)) {
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_END;
		goto end;
	}

	/* Consume one message  */
	next_status = bt_self_component_port_input_message_iterator_next(
		dummy->msg_iter, &msgs, &count);
	switch (next_status) {
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_OK:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;

		for (i = 0; i < count; i++) {
			bt_message_put_ref(msgs[i]);
		}

		break;
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_AGAIN:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_AGAIN;
		goto end;
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_END:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_END;
		goto end;
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_ERROR:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_ERROR;
		goto end;
	case BT_MESSAGE_ITERATOR_NEXT_STATUS_MEMORY_ERROR:
		status = BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_MEMORY_ERROR;
		goto end;
	default:
		break;
	}

end:
	return status;
}
