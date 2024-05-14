/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef BABELTRACE_LIB_GRAPH_COMPONENT_SOURCE_H
#define BABELTRACE_LIB_GRAPH_COMPONENT_SOURCE_H

#include "component.h"

struct bt_component_source {
	struct bt_component parent;
};

struct bt_component *bt_component_source_create(void);

#endif /* BABELTRACE_LIB_GRAPH_COMPONENT_SOURCE_H */
