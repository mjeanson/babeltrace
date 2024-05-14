/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_BINDINGS_PYTHON_BT2_BT2_NATIVE_BT_QUERY_EXEC_I_H
#define BABELTRACE_BINDINGS_PYTHON_BT2_BT2_NATIVE_BT_QUERY_EXEC_I_H

static
bt_query_executor *bt_bt2_query_executor_create(
		const bt_component_class *component_class, const char *object,
		const bt_value *params, PyObject *py_obj)
{
	return bt_query_executor_create_with_method_data(component_class,
		object, params, py_obj == Py_None ? NULL : py_obj);
}

#endif /* BABELTRACE_BINDINGS_PYTHON_BT2_BT2_NATIVE_BT_QUERY_EXEC_I_H */
