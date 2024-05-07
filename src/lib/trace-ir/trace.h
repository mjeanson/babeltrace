/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef BABELTRACE_LIB_TRACE_IR_TRACE_H
#define BABELTRACE_LIB_TRACE_IR_TRACE_H

#include <babeltrace2/trace-ir/trace.h>
#include <babeltrace2/trace-ir/field-class.h>
#include <babeltrace2/trace-ir/field.h>
#include "lib/object.h"
#include <babeltrace2/value.h>
#include <babeltrace2/types.h>
#include <glib.h>
#include <stdbool.h>
#include <sys/types.h>
#include "common/uuid.h"

#include "stream-class.h"
#include "trace-class.h"

struct bt_trace {
	struct bt_object base;

	/* Owned by this */
	struct bt_value *user_attributes;

	/* Owned by this */
	struct bt_trace_class *class;

	gchar *ns;
	gchar *name;

	union {
		/* Used for MIP == 0 */
		struct {
			bt_uuid_t uuid;

			/* NULL or `uuid` above */
			bt_uuid value;
		} uuid;

		/* Used for MIP >= 1 */
		gchar *uid;
	} uid_or_uuid;

	struct bt_value *environment;

	/* Array of `struct bt_stream *` */
	GPtrArray *streams;

	/*
	 * Stream class (weak, owned by owned trace class) to number of
	 * instantiated streams, used to automatically assign stream IDs
	 * per stream class within this trace.
	 */
	GHashTable *stream_classes_stream_count;

	GArray *destruction_listeners;
	bool frozen;
};

void _bt_trace_freeze(const struct bt_trace *trace);

#ifdef BT_DEV_MODE
# define bt_trace_freeze		_bt_trace_freeze
#else
# define bt_trace_freeze(_trace)
#endif

void bt_trace_add_stream(struct bt_trace *trace, struct bt_stream *stream);

uint64_t bt_trace_get_automatic_stream_id(const struct bt_trace *trace,
		const struct bt_stream_class *stream_class);

#endif /* BABELTRACE_LIB_TRACE_IR_TRACE_H */
