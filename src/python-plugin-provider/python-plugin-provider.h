/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PYTHON_PLUGIN_PROVIDER_PYTHON_PLUGIN_PROVIDER_H
#define BABELTRACE_PYTHON_PLUGIN_PROVIDER_PYTHON_PLUGIN_PROVIDER_H

#include <babeltrace2/babeltrace.h>
#include <stdbool.h>

extern
int bt_plugin_python_create_all_from_file(const char *path,
		bool fail_on_load_error,
		struct bt_plugin_set **plugin_set_out);

#endif /* BABELTRACE_PYTHON_PLUGIN_PROVIDER_PYTHON_PLUGIN_PROVIDER_H */
