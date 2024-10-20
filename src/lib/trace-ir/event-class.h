/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef BABELTRACE_LIB_TRACE_IR_EVENT_CLASS_H
#define BABELTRACE_LIB_TRACE_IR_EVENT_CLASS_H

#include <babeltrace2/trace-ir/field-class.h>
#include <babeltrace2/trace-ir/field.h>
#include <babeltrace2/value.h>
#include <babeltrace2/trace-ir/stream-class.h>
#include <babeltrace2/trace-ir/stream.h>
#include <babeltrace2/trace-ir/event-class.h>
#include "lib/object.h"
#include "common/assert.h"
#include "lib/object-pool.h"
#include "lib/property.h"
#include <glib.h>
#include <stdbool.h>

struct bt_event_class {
	struct bt_object base;
	struct bt_field_class *specific_context_fc;
	struct bt_field_class *payload_fc;

	/* Owned by this */
	struct bt_value *user_attributes;

	gchar *ns;
	gchar *name;
	gchar *uid;

	uint64_t id;
	struct bt_property_uint log_level;

	gchar *emf_uri;

	/* Pool of `struct bt_event *` */
	struct bt_object_pool event_pool;

	bool frozen;
};

void _bt_event_class_freeze(const struct bt_event_class *event_class);

#ifdef BT_DEV_MODE
# define bt_event_class_freeze		_bt_event_class_freeze
#else
# define bt_event_class_freeze(_ec)
#endif

static inline
struct bt_stream_class *bt_event_class_borrow_stream_class_inline(
		const struct bt_event_class *event_class)
{
	BT_ASSERT_DBG(event_class);
	return (void *) bt_object_borrow_parent(&event_class->base);
}

#endif /* BABELTRACE_LIB_TRACE_IR_EVENT_CLASS_H */
