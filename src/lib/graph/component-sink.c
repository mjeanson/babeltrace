/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#define BT_LOG_TAG "LIB/COMPONENT-SINK"
#include "lib/logging.h"

#include "common/assert.h"
#include "lib/assert-cond.h"
#include "compat/compiler.h"
#include <babeltrace2/value.h>
#include <babeltrace2/graph/self-component.h>
#include <babeltrace2/graph/component.h>
#include <babeltrace2/graph/graph.h>

#include "component-sink.h"
#include "component.h"
#include "graph.h"
#include "lib/func-status.h"

BT_HIDDEN
void bt_component_sink_destroy(
		struct bt_component *component __attribute__((unused)))
{
}

BT_HIDDEN
struct bt_component *bt_component_sink_create(
		const struct bt_component_class *class __attribute__((unused)))
{
	struct bt_component_sink *sink = NULL;

	sink = g_new0(struct bt_component_sink, 1);
	if (!sink) {
		BT_LIB_LOGE_APPEND_CAUSE(
			"Failed to allocate one sink component.");
		goto end;
	}

end:
	return (void *) sink;
}

const bt_component_class_sink *
bt_component_sink_borrow_class_const(
		const bt_component_sink *component)
{
	struct bt_component_class *cls;

	BT_ASSERT_PRE_DEV_COMP_NON_NULL(component);

	cls = component->parent.class;

	BT_ASSERT_DBG(cls);
	BT_ASSERT_DBG(cls->type == BT_COMPONENT_CLASS_TYPE_SINK);

	return (bt_component_class_sink *) cls;
}

uint64_t bt_component_sink_get_input_port_count(
		const struct bt_component_sink *component)
{
	/* bt_component_get_input_port_count() checks preconditions */
	return bt_component_get_input_port_count((void *) component, __func__);
}

const struct bt_port_input *
bt_component_sink_borrow_input_port_by_name_const(
		const struct bt_component_sink *component, const char *name)
{
	/*
	 * bt_component_borrow_input_port_by_name() logs details/errors
	 * and checks preconditions.
	 */
	return bt_component_borrow_input_port_by_name((void *) component, name,
		__func__);
}

struct bt_self_component_port_input *
bt_self_component_sink_borrow_input_port_by_name(
		struct bt_self_component_sink *component, const char *name)
{
	/*
	 * bt_component_borrow_input_port_by_name() logs details/errors
	 * and checks preconditions.
	 */
	return (void *) bt_component_borrow_input_port_by_name(
		(void *) component, name, __func__);
}

const struct bt_port_input *bt_component_sink_borrow_input_port_by_index_const(
		const struct bt_component_sink *component, uint64_t index)
{
	/*
	 * bt_component_borrow_input_port_by_index() logs details/errors
	 * and checks preconditions.
	 */
	return bt_component_borrow_input_port_by_index(
		(void *) component, index, __func__);
}

struct bt_self_component_port_input *
bt_self_component_sink_borrow_input_port_by_index(
		struct bt_self_component_sink *component, uint64_t index)
{
	/*
	 * bt_component_borrow_input_port_by_index() logs details/errors
	 * and checks preconditions.
	 */
	return (void *) bt_component_borrow_input_port_by_index(
		(void *) component, index, __func__);
}

enum bt_self_component_add_port_status bt_self_component_sink_add_input_port(
		struct bt_self_component_sink *self_comp,
		const char *name, void *user_data,
		struct bt_self_component_port_input **self_port)
{
	enum bt_self_component_add_port_status status;
	struct bt_port *port = NULL;
	struct bt_component *comp = (void *) self_comp;

	BT_ASSERT_PRE_NO_ERROR();

	/*
	 * bt_component_add_input_port() logs details/errors and checks
	 * preconditions.
	 */
	status = bt_component_add_input_port(comp, name, user_data, &port,
		__func__);
	if (status != BT_FUNC_STATUS_OK) {
		goto end;
	}

	if (self_port) {
		/* Move reference to user */
		*self_port = (void *) port;
	}

end:
	bt_object_put_ref(port);
	return status;
}

bt_bool bt_self_component_sink_is_interrupted(
		const struct bt_self_component_sink *self_comp)
{
	struct bt_component *comp = (void *) self_comp;

	BT_ASSERT_PRE_COMP_NON_NULL(comp);
	return (bt_bool) bt_graph_is_interrupted(
		bt_component_borrow_graph(comp));
}

void bt_component_sink_get_ref(
		const struct bt_component_sink *component_sink)
{
	bt_object_get_ref(component_sink);
}

void bt_component_sink_put_ref(
		const struct bt_component_sink *component_sink)
{
	bt_object_put_ref(component_sink);
}
