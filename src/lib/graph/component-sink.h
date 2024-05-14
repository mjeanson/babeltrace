/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef BABELTRACE_LIB_GRAPH_COMPONENT_SINK_H
#define BABELTRACE_LIB_GRAPH_COMPONENT_SINK_H

#include <stdbool.h>

#include "compat/compiler.h"
#include <babeltrace2/graph/component.h>

#include "component.h"

struct bt_component_sink {
	struct bt_component parent;
	bool graph_is_configured_method_called;
};

struct bt_component *bt_component_sink_create(void);

#endif /* BABELTRACE_LIB_GRAPH_COMPONENT_SINK_H */
