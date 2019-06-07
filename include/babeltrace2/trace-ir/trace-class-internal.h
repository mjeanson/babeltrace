#ifndef BABELTRACE_TRACE_IR_TRACE_CLASS_INTERNAL_H
#define BABELTRACE_TRACE_IR_TRACE_CLASS_INTERNAL_H

/*
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <babeltrace2/assert-pre-internal.h>
#include <babeltrace2/trace-ir/trace-class.h>
#include <babeltrace2/trace-ir/stream-class-internal.h>
#include <babeltrace2/trace-ir/field-class.h>
#include <babeltrace2/trace-ir/field.h>
#include <babeltrace2/trace-ir/attributes-internal.h>
#include <babeltrace2/trace-ir/clock-class-internal.h>
#include <babeltrace2/object-internal.h>
#include <babeltrace2/object-pool-internal.h>
#include <babeltrace2/babeltrace-internal.h>
#include <babeltrace2/value.h>
#include <babeltrace2/types.h>
#include <glib.h>
#include <sys/types.h>
#include <babeltrace2/compat/uuid-internal.h>

struct bt_trace_class {
	struct bt_object base;

	struct {
		GString *str;

		/* NULL or `str->str` above */
		const char *value;
	} name;

	struct {
		uint8_t uuid[BABELTRACE_UUID_LEN];

		/* NULL or `uuid` above */
		bt_uuid value;
	} uuid;

	struct bt_value *environment;

	/* Array of `struct bt_stream_class *` */
	GPtrArray *stream_classes;

	bool assigns_automatic_stream_class_id;
	GArray *destruction_listeners;
	bool frozen;
};

BT_HIDDEN
void _bt_trace_class_freeze(const struct bt_trace_class *trace_class);

#ifdef BT_DEV_MODE
# define bt_trace_class_freeze		_bt_trace_class_freeze
#else
# define bt_trace_class_freeze(_tc)
#endif

#endif /* BABELTRACE_TRACE_IR_TRACE_CLASS_INTERNAL_H */
