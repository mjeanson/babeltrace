/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_TEXT_DETAILS_DETAILS_H
#define BABELTRACE_PLUGINS_TEXT_DETAILS_DETAILS_H

#include <glib.h>
#include <babeltrace2/babeltrace.h>
#include <stdbool.h>

/*
 * This structure contains a hash table which maps trace IR stream class
 * and event class addresses to whether or not they have been printed
 * already during the lifetime of the component.
 *
 * It is safe to keep the addresses (weak references) in this hash table
 * as long as the trace class to which the structure is associated
 * exists because it's not possible to remove stream classes from a
 * trace class and event classes from a stream class.
 */
struct details_trace_class_meta {
	/*
	 * Stream class or event class address (`const void *`) ->
	 * `guint` (as a pointer)
	 *
	 * This acts as a set in fact; we don't care about the values,
	 * but we put 1 so that we can use g_hash_table_lookup() to know
	 * whether or not the hash table contains a given key
	 * (g_hash_table_lookup() returns `NULL` when not found, but
	 * also when the value is `NULL`).
	 */
	GHashTable *objects;

	/*
	 * Trace class destruction listener ID (`UINT64_C(-1)` if
	 * there's no listener ID.
	 */
	bt_listener_id tc_destruction_listener_id;
};

/*
 * An entry of the `traces` hash table of a
 * `struct details_comp` structure.
 */
struct details_trace {
	/* Unique ID of this trace within the lifetime of the component */
	uint64_t unique_id;

	/*
	 * Trace destruction listener ID (`UINT64_C(-1)` if there's no
	 * listener ID.
	 */
	bt_listener_id trace_destruction_listener_id;
};

/* A `sink.text.details` component */
struct details_comp {
	bt_logging_level log_level;
	bt_self_component *self_comp;
	uint64_t mip_version;

	/* Component's configuration */
	struct {
		/* Write data objects */
		bool with_data;

		/* Write metadata objects */
		bool with_meta;

		/*
		 * Compact mode: each line is a single message, and
		 * there are no extended message properties and
		 * event/packet fields. `with_meta` can still be true in
		 * compact mode, printing the full metadata objects, but
		 * making the messages compact.
		 */
		bool compact;

		/* Colorize output */
		bool with_color;

		/* Write message's time */
		bool with_time;

		/* Write trace's name */
		bool with_trace_name;

		/* Write stream class's namespace */
		bool with_stream_class_ns;

		/* Write stream class's name */
		bool with_stream_class_name;

		/* Write stream's name */
		bool with_stream_name;

		/* Write UUID */
		bool with_uuid;

		/* Write UID */
		bool with_uid;
	} cfg;

	/*
	 * `const bt_trace_class *` (weak) ->
	 * `struct details_trace_class_meta *` (owned by this)
	 *
	 * The key (trace class object) is weak. An entry is added, if
	 * `cfg.with_meta` above is true, when first encountering a
	 * trace class. An entry is removed when a trace class is
	 * destroyed or when the component is finalized.
	 */
	GHashTable *meta;

	/*
	 * `const bt_trace *` (weak) ->
	 * `struct details_trace *` (owner by this)
	 *
	 * This hash table associates a trace object to a unique ID
	 * within the lifetime of this component. This is used to easily
	 * follow the messages of a given trace/stream when reading the
	 * text output of the component. We cannot use the actual stream
	 * ID properties for this because many streams can share the
	 * same ID (with different stream classes or different traces).
	 *
	 * When adding an entry, the unique ID to use is
	 * `next_unique_trace_id`.
	 *
	 * An entry is added when first encountering a trace. An entry
	 * is removed when a trace is destroyed or when the component is
	 * finalized.
	 */
	GHashTable *traces;
	uint32_t next_unique_trace_id;

	/* Upstream message iterator */
	bt_message_iterator *msg_iter;

	/*
	 * True if this component printed something. This is used to
	 * prepend a newline to the next message string instead of
	 * appending it so that the last printed message is not followed
	 * with an empty line.
	 */
	bool printed_something;

	/* Current message's output buffer */
	GString *str;
};

bt_component_class_get_supported_mip_versions_method_status
details_supported_mip_versions(bt_self_component_class_sink *self_component_class,
		const bt_value *params, void *initialize_method_data,
		bt_logging_level logging_level,
		bt_integer_range_set_unsigned *supported_versions);

bt_component_class_initialize_method_status details_init(
		bt_self_component_sink *component,
		bt_self_component_sink_configuration *config,
		const bt_value *params, void *init_method_data);

void details_finalize(bt_self_component_sink *component);

bt_component_class_sink_graph_is_configured_method_status details_graph_is_configured(
		bt_self_component_sink *comp);

bt_component_class_sink_consume_method_status details_consume(bt_self_component_sink *component);

void details_destroy_details_trace_class_meta(
		struct details_trace_class_meta *details_trace_class_meta);

struct details_trace_class_meta *details_create_details_trace_class_meta(void);

#endif /* BABELTRACE_PLUGINS_TEXT_DETAILS_DETAILS_H */
