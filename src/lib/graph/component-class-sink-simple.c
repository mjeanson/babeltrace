/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2019 Philippe Proulx <pproulx@efficios.com>
 */

#define BT_LOG_TAG "LIB/COMPONENT-CLASS-SINK-SIMPLE"
#include "lib/logging.h"

#include "common/assert.h"
#include "common/common.h"
#include "lib/assert-cond.h"
#include "lib/object.h"
#include <babeltrace2/graph/component-class.h>
#include <babeltrace2/graph/self-component-port.h>
#include <babeltrace2/graph/self-component.h>
#include <babeltrace2/graph/message-iterator.h>
#include <glib.h>

#include "component-class-sink-simple.h"
#include "lib/func-status.h"

/*
 * We keep a single simple sink component class reference. It's created
 * the first time bt_component_class_sink_simple_borrow() is called and
 * put by the put_simple_sink_component_class() library destructor.
 */
static
struct bt_component_class_sink *simple_comp_cls;

struct simple_sink_data {
	bt_message_iterator *msg_iter;
	struct simple_sink_init_method_data init_method_data;
};

static
void simple_sink_data_destroy(struct simple_sink_data *data)
{
	if (data) {
		BT_OBJECT_PUT_REF_AND_RESET(data->msg_iter);
		g_free(data);
	}
}

static
enum bt_component_class_initialize_method_status simple_sink_init(
		bt_self_component_sink *self_comp,
		bt_self_component_sink_configuration *config __attribute__((unused)),
		const struct bt_value *params __attribute__((unused)),
		void *init_method_data)
{
	int status = BT_FUNC_STATUS_OK;
	struct simple_sink_data *data = NULL;

	data = g_new0(struct simple_sink_data, 1);
	if (!data) {
		BT_LIB_LOGE_APPEND_CAUSE(
			"Failed to allocate simple sink component private data.");
		status = BT_FUNC_STATUS_MEMORY_ERROR;
		goto end;
	}

	BT_ASSERT(init_method_data);
	data->init_method_data =
		*((struct simple_sink_init_method_data *) init_method_data);

	/* Add input port */
	status = bt_self_component_sink_add_input_port(self_comp, "in",
		NULL, NULL);
	if (status != BT_FUNC_STATUS_OK) {
		BT_LIB_LOGE_APPEND_CAUSE(
			"Cannot add input port to simple sink component.");
		goto end;
	}

	/* Transfer ownership to component */
	bt_self_component_set_data(
		bt_self_component_sink_as_self_component(self_comp), data);
	data = NULL;

end:
	simple_sink_data_destroy(data);
	return status;
}

static
void simple_sink_finalize(struct bt_self_component_sink *self_comp)
{
	struct simple_sink_data *data = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_comp));

	BT_ASSERT(data);

	if (data->init_method_data.finalize_func) {
		/* Call user's finalization function */
		data->init_method_data.finalize_func(
			data->init_method_data.user_data);
	}

	simple_sink_data_destroy(data);
}

static
enum bt_component_class_sink_graph_is_configured_method_status
simple_sink_graph_is_configured(
	bt_self_component_sink *self_comp)
{
	bt_component_class_sink_graph_is_configured_method_status status;
	bt_message_iterator_create_from_sink_component_status
		msg_iter_status;
	struct simple_sink_data *data = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_comp));

	struct bt_self_component_port_input *self_port =
		bt_self_component_sink_borrow_input_port_by_name(self_comp,
			"in");

	if (!bt_port_is_connected(bt_self_component_port_as_port(
			bt_self_component_port_input_as_self_component_port(self_port)))) {
		BT_LIB_LOGE_APPEND_CAUSE(
			"Simple sink component's input port is not connected: "
			"%![comp-]+c, %![port-]+p", self_comp, self_port);
		status = BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_ERROR;
		goto end;
	}

	BT_ASSERT(data);
	msg_iter_status = bt_message_iterator_create_from_sink_component(
		self_comp, self_port, &data->msg_iter);
	if (msg_iter_status != BT_MESSAGE_ITERATOR_CREATE_FROM_SINK_COMPONENT_STATUS_OK) {
		BT_LIB_LOGE_APPEND_CAUSE(
			"Cannot create input port message iterator: "
			"%![comp-]+c, %![port-]+p", self_comp, self_port);
		status = (int) msg_iter_status;
		goto end;
	}

	if (data->init_method_data.init_func) {
		bt_graph_simple_sink_component_initialize_func_status init_status;

		/* Call user's initialization function */
		init_status = data->init_method_data.init_func(data->msg_iter,
			data->init_method_data.user_data);
		if (init_status != BT_GRAPH_SIMPLE_SINK_COMPONENT_INITIALIZE_FUNC_STATUS_OK) {
			BT_LIB_LOGW_APPEND_CAUSE(
				"Simple sink component's user's initialization function failed: "
				"status=%s, %![comp-]+c, %![port-]+p",
				bt_common_func_status_string(init_status),
				self_comp, self_port);
			status = (int) init_status;
			goto end;
		}
	}

	status = BT_COMPONENT_CLASS_SINK_GRAPH_IS_CONFIGURED_METHOD_STATUS_OK;

end:
	return status;
}

static
enum bt_component_class_sink_consume_method_status simple_sink_consume(
		struct bt_self_component_sink *self_comp)
{
	int status;
	struct simple_sink_data *data = bt_self_component_get_data(
		bt_self_component_sink_as_self_component(self_comp));

	BT_ASSERT_DBG(data);
	BT_ASSERT_DBG(data->init_method_data.consume_func);
	BT_ASSERT_DBG(data->msg_iter);

	/* Call user's "consume" function */
	status = data->init_method_data.consume_func(data->msg_iter,
		data->init_method_data.user_data);
	if (status < 0) {
		BT_LIB_LOGW_APPEND_CAUSE(
			"Simple sink component's user's \"consume\" function failed: "
			"status=%s, %![comp-]+c",
			bt_common_func_status_string(status), self_comp);
	}

	return status;
}

BT_HIDDEN
struct bt_component_class_sink *bt_component_class_sink_simple_borrow(void)
{
	enum bt_component_class_set_method_status set_method_status;

	if (simple_comp_cls) {
		goto end;
	}

	simple_comp_cls = bt_component_class_sink_create("simple-sink",
		simple_sink_consume);
	if (!simple_comp_cls) {
		BT_LIB_LOGE_APPEND_CAUSE(
			"Cannot create simple sink component class.");
		goto end;
	}

	set_method_status = bt_component_class_sink_set_initialize_method(
		simple_comp_cls, simple_sink_init);
	BT_ASSERT(set_method_status == BT_FUNC_STATUS_OK);
	set_method_status = bt_component_class_sink_set_finalize_method(
		simple_comp_cls, simple_sink_finalize);
	BT_ASSERT(set_method_status == BT_FUNC_STATUS_OK);
	set_method_status = bt_component_class_sink_set_graph_is_configured_method(
		simple_comp_cls, simple_sink_graph_is_configured);
	BT_ASSERT(set_method_status == BT_FUNC_STATUS_OK);

end:
	return simple_comp_cls;
}

__attribute__((destructor)) static
void put_simple_sink_component_class(void) {
	BT_OBJECT_PUT_REF_AND_RESET(simple_comp_cls);
}
