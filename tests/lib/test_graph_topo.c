/*
 * test_graph_topo.c
 *
 * Copyright 2017 - Philippe Proulx <pproulx@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <babeltrace2/babeltrace.h>
#include <babeltrace2/assert-internal.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <glib.h>

#include "tap/tap.h"

#define NR_TESTS	48

enum event_type {
	SRC_COMP_ACCEPT_OUTPUT_PORT_CONNECTION,
	SINK_COMP_ACCEPT_INPUT_PORT_CONNECTION,
	SRC_COMP_OUTPUT_PORT_CONNECTED,
	SINK_COMP_INPUT_PORT_CONNECTED,
	GRAPH_SRC_OUTPUT_PORT_ADDED,
	GRAPH_SINK_INPUT_PORT_ADDED,
	GRAPH_SRC_SINK_PORTS_CONNECTED,
};

enum test {
	TEST_EMPTY_GRAPH,
	TEST_SIMPLE,
	TEST_SRC_PORT_CONNECTED_ERROR,
	TEST_SINK_PORT_CONNECTED_ERROR,
	TEST_SRC_ADDS_PORT_IN_PORT_CONNECTED,
};

struct event {
	enum event_type type;

	union {
		struct {
			const bt_component *comp;
			const bt_port *self_port;
			const bt_port *other_port;
		} src_comp_accept_output_port_connection;

		struct {
			const bt_component *comp;
			const bt_port *self_port;
			const bt_port *other_port;
		} sink_comp_accept_input_port_connection;

		struct {
			const bt_component *comp;
			const bt_port *self_port;
			const bt_port *other_port;
		} src_comp_output_port_connected;

		struct {
			const bt_component *comp;
			const bt_port *self_port;
			const bt_port *other_port;
		} sink_comp_input_port_connected;

		struct {
			const bt_component *comp;
			const bt_port *port;
		} graph_src_output_port_added;

		struct {
			const bt_component *comp;
			const bt_port *port;
		} graph_sink_input_port_added;

		struct {
			const bt_component *upstream_comp;
			const bt_component *downstream_comp;
			const bt_port *upstream_port;
			const bt_port *downstream_port;
		} graph_src_sink_ports_connected;
	} data;
};

static GArray *events;
static bt_component_class_source *src_comp_class;
static bt_component_class_sink *sink_comp_class;
static enum test current_test;

static
void clear_events(void)
{
	g_array_set_size(events, 0);
}

static
void append_event(struct event *event)
{
	g_array_append_val(events, *event);
}

static
bool compare_events(struct event *ev_a, struct event *ev_b)
{
	if (ev_a->type != ev_b->type) {
		return false;
	}

	switch (ev_a->type) {
		case SRC_COMP_ACCEPT_OUTPUT_PORT_CONNECTION:
			if (ev_a->data.src_comp_accept_output_port_connection.comp !=
					ev_b->data.src_comp_accept_output_port_connection.comp) {
				return false;
			}

			if (ev_a->data.src_comp_accept_output_port_connection.self_port !=
					ev_b->data.src_comp_accept_output_port_connection.self_port) {
				return false;
			}

			if (ev_a->data.src_comp_accept_output_port_connection.other_port !=
					ev_b->data.src_comp_accept_output_port_connection.other_port) {
				return false;
			}
			break;
		case SINK_COMP_ACCEPT_INPUT_PORT_CONNECTION:
			if (ev_a->data.sink_comp_accept_input_port_connection.comp !=
					ev_b->data.sink_comp_accept_input_port_connection.comp) {
				return false;
			}

			if (ev_a->data.sink_comp_accept_input_port_connection.self_port !=
					ev_b->data.sink_comp_accept_input_port_connection.self_port) {
				return false;
			}

			if (ev_a->data.sink_comp_accept_input_port_connection.other_port !=
					ev_b->data.sink_comp_accept_input_port_connection.other_port) {
				return false;
			}
			break;
		case SRC_COMP_OUTPUT_PORT_CONNECTED:
			if (ev_a->data.src_comp_output_port_connected.comp !=
					ev_b->data.src_comp_output_port_connected.comp) {
				return false;
			}

			if (ev_a->data.src_comp_output_port_connected.self_port !=
					ev_b->data.src_comp_output_port_connected.self_port) {
				return false;
			}

			if (ev_a->data.src_comp_output_port_connected.other_port !=
					ev_b->data.src_comp_output_port_connected.other_port) {
				return false;
			}
			break;
		case SINK_COMP_INPUT_PORT_CONNECTED:
			if (ev_a->data.sink_comp_input_port_connected.comp !=
					ev_b->data.sink_comp_input_port_connected.comp) {
				return false;
			}

			if (ev_a->data.sink_comp_input_port_connected.self_port !=
					ev_b->data.sink_comp_input_port_connected.self_port) {
				return false;
			}

			if (ev_a->data.sink_comp_input_port_connected.other_port !=
					ev_b->data.sink_comp_input_port_connected.other_port) {
				return false;
			}
			break;
		case GRAPH_SRC_OUTPUT_PORT_ADDED:
			if (ev_a->data.graph_src_output_port_added.comp !=
					ev_b->data.graph_src_output_port_added.comp) {
				return false;
			}

			if (ev_a->data.graph_src_output_port_added.port !=
					ev_b->data.graph_src_output_port_added.port) {
				return false;
			}
			break;
		case GRAPH_SINK_INPUT_PORT_ADDED:
			if (ev_a->data.graph_sink_input_port_added.comp !=
					ev_b->data.graph_sink_input_port_added.comp) {
				return false;
			}

			if (ev_a->data.graph_sink_input_port_added.port !=
					ev_b->data.graph_sink_input_port_added.port) {
				return false;
			}
			break;
		case GRAPH_SRC_SINK_PORTS_CONNECTED:
			if (ev_a->data.graph_src_sink_ports_connected.upstream_comp !=
					ev_b->data.graph_src_sink_ports_connected.upstream_comp) {
				return false;
			}

			if (ev_a->data.graph_src_sink_ports_connected.downstream_comp !=
					ev_b->data.graph_src_sink_ports_connected.downstream_comp) {
				return false;
			}

			if (ev_a->data.graph_src_sink_ports_connected.upstream_port !=
					ev_b->data.graph_src_sink_ports_connected.upstream_port) {
				return false;
			}

			if (ev_a->data.graph_src_sink_ports_connected.downstream_port !=
					ev_b->data.graph_src_sink_ports_connected.downstream_port) {
				return false;
			}
			break;
		default:
			abort();
	}

	return true;
}

static
bool has_event(struct event *event)
{
	size_t i;

	for (i = 0; i < events->len; i++) {
		struct event *ev = &g_array_index(events, struct event, i);

		if (compare_events(event, ev)) {
			return true;
		}
	}

	return false;
}

static
size_t event_pos(struct event *event)
{
	size_t i;

	for (i = 0; i < events->len; i++) {
		struct event *ev = &g_array_index(events, struct event, i);

		if (compare_events(event, ev)) {
			return i;
		}
	}

	return SIZE_MAX;
}

static
bt_self_message_iterator_status src_iter_next(
		bt_self_message_iterator *self_iterator,
		bt_message_array_const msgs, uint64_t capacity,
		uint64_t *count)
{
	return BT_SELF_MESSAGE_ITERATOR_STATUS_ERROR;
}

static
bt_self_component_status src_accept_output_port_connection(
		bt_self_component_source *self_comp,
		bt_self_component_port_output *self_comp_port,
		const bt_port_input *other_port)
{
	struct event event = {
		.type = SRC_COMP_ACCEPT_OUTPUT_PORT_CONNECTION,
		.data.src_comp_accept_output_port_connection = {
			.comp = bt_self_component_as_component(
				bt_self_component_source_as_self_component(
					self_comp)),
			.self_port = bt_self_component_port_as_port(
				bt_self_component_port_output_as_self_component_port(
					self_comp_port)),
			.other_port = bt_port_input_as_port_const(other_port),
		},
	};

	append_event(&event);
	return BT_SELF_COMPONENT_STATUS_OK;
}

static
bt_self_component_status sink_accept_input_port_connection(
		bt_self_component_sink *self_comp,
		bt_self_component_port_input *self_comp_port,
		const bt_port_output *other_port)
{
	struct event event = {
		.type = SINK_COMP_ACCEPT_INPUT_PORT_CONNECTION,
		.data.sink_comp_accept_input_port_connection = {
			.comp = bt_self_component_as_component(
				bt_self_component_sink_as_self_component(
					self_comp)),
			.self_port = bt_self_component_port_as_port(
				bt_self_component_port_input_as_self_component_port(
					self_comp_port)),
			.other_port = bt_port_output_as_port_const(other_port),
		},
	};

	append_event(&event);
	return BT_SELF_COMPONENT_STATUS_OK;
}

static
bt_self_component_status src_output_port_connected(
		bt_self_component_source *self_comp,
		bt_self_component_port_output *self_comp_port,
		const bt_port_input *other_port)
{
	int ret;
	struct event event = {
		.type = SRC_COMP_OUTPUT_PORT_CONNECTED,
		.data.src_comp_output_port_connected = {
			.comp = bt_self_component_as_component(
				bt_self_component_source_as_self_component(
					self_comp)),
			.self_port = bt_self_component_port_as_port(
				bt_self_component_port_output_as_self_component_port(
					self_comp_port)),
			.other_port = bt_port_input_as_port_const(other_port),
		},
	};

	append_event(&event);

	switch (current_test) {
	case TEST_SRC_ADDS_PORT_IN_PORT_CONNECTED:
		ret = bt_self_component_source_add_output_port(
			self_comp, "hello", NULL, NULL);
		BT_ASSERT(ret == 0);
		break;
	case TEST_SRC_PORT_CONNECTED_ERROR:
		return BT_SELF_COMPONENT_STATUS_ERROR;
	default:
		break;
	}

	return BT_SELF_COMPONENT_STATUS_OK;
}

static
bt_self_component_status sink_input_port_connected(
		bt_self_component_sink *self_comp,
		bt_self_component_port_input *self_comp_port,
		const bt_port_output *other_port)
{
	struct event event = {
		.type = SINK_COMP_INPUT_PORT_CONNECTED,
		.data.sink_comp_input_port_connected = {
			.comp = bt_self_component_as_component(
				bt_self_component_sink_as_self_component(
					self_comp)),
			.self_port = bt_self_component_port_as_port(
				bt_self_component_port_input_as_self_component_port(
					self_comp_port)),
			.other_port = bt_port_output_as_port_const(other_port),
		},
	};

	append_event(&event);

	if (current_test == TEST_SINK_PORT_CONNECTED_ERROR) {
		return BT_SELF_COMPONENT_STATUS_ERROR;
	} else {
		return BT_SELF_COMPONENT_STATUS_OK;
	}
}

static
bt_self_component_status src_init(
	bt_self_component_source *self_comp,
	const bt_value *params, void *init_method_data)
{
	int ret;

	ret = bt_self_component_source_add_output_port(
		self_comp, "out", NULL, NULL);
	BT_ASSERT(ret == 0);
	return BT_SELF_COMPONENT_STATUS_OK;
}

static
bt_self_component_status sink_init(
	bt_self_component_sink *self_comp,
	const bt_value *params, void *init_method_data)
{
	int ret;

	ret = bt_self_component_sink_add_input_port(self_comp,
		"in", NULL, NULL);
	BT_ASSERT(ret == 0);
	return BT_SELF_COMPONENT_STATUS_OK;
}

static
bt_self_component_status sink_consume(
		bt_self_component_sink *self_comp)
{
	return BT_SELF_COMPONENT_STATUS_OK;
}

static
bt_graph_listener_status graph_src_output_port_added(
		const bt_component_source *comp, const bt_port_output *port,
		void *data)
{
	struct event event = {
		.type = GRAPH_SRC_OUTPUT_PORT_ADDED,
		.data.graph_src_output_port_added = {
			.comp = bt_component_source_as_component_const(comp),
			.port = bt_port_output_as_port_const(port),
		},
	};

	append_event(&event);

	return BT_GRAPH_LISTENER_STATUS_OK;
}

static
bt_graph_listener_status graph_sink_input_port_added(
		const bt_component_sink *comp, const bt_port_input *port,
		void *data)
{
	struct event event = {
		.type = GRAPH_SINK_INPUT_PORT_ADDED,
		.data.graph_sink_input_port_added = {
			.comp = bt_component_sink_as_component_const(comp),
			.port = bt_port_input_as_port_const(port),
		},
	};

	append_event(&event);

	return BT_GRAPH_LISTENER_STATUS_OK;
}

static
bt_graph_listener_status graph_src_sink_ports_connected(
		const bt_component_source *upstream_comp,
		const bt_component_sink *downstream_comp,
		const bt_port_output *upstream_port,
		const bt_port_input *downstream_port, void *data)
{
	struct event event = {
		.type = GRAPH_SRC_SINK_PORTS_CONNECTED,
		.data.graph_src_sink_ports_connected = {
			.upstream_comp =
				bt_component_source_as_component_const(upstream_comp),
				.downstream_comp =
				bt_component_sink_as_component_const(downstream_comp),
				.upstream_port =
				bt_port_output_as_port_const(upstream_port),
				.downstream_port =
				bt_port_input_as_port_const(downstream_port),
		},
	};

	append_event(&event);

	return BT_GRAPH_LISTENER_STATUS_OK;
}

static
void init_test(void)
{
	int ret;

	src_comp_class = bt_component_class_source_create(
		"src", src_iter_next);
	BT_ASSERT(src_comp_class);
	ret = bt_component_class_source_set_init_method(
		src_comp_class, src_init);
	BT_ASSERT(ret == 0);
	ret = bt_component_class_source_set_accept_output_port_connection_method(
		src_comp_class, src_accept_output_port_connection);
	BT_ASSERT(ret == 0);
	ret = bt_component_class_source_set_output_port_connected_method(
		src_comp_class, src_output_port_connected);
	BT_ASSERT(ret == 0);
	sink_comp_class = bt_component_class_sink_create("sink",
		sink_consume);
	BT_ASSERT(sink_comp_class);
	ret = bt_component_class_sink_set_init_method(sink_comp_class,
		sink_init);
	BT_ASSERT(ret == 0);
	ret = bt_component_class_sink_set_accept_input_port_connection_method(
		sink_comp_class, sink_accept_input_port_connection);
	BT_ASSERT(ret == 0);
	ret = bt_component_class_sink_set_input_port_connected_method(
		sink_comp_class, sink_input_port_connected);
	BT_ASSERT(ret == 0);
	events = g_array_new(FALSE, TRUE, sizeof(struct event));
	BT_ASSERT(events);
}

static
void fini_test(void)
{
	bt_component_class_source_put_ref(src_comp_class);
	bt_component_class_sink_put_ref(sink_comp_class);
	g_array_free(events, TRUE);
}

static
const bt_component_source *create_src(bt_graph *graph)
{
	const bt_component_source *comp;
	int ret;

	ret = bt_graph_add_source_component(graph, src_comp_class,
		"src-comp", NULL, &comp);
	BT_ASSERT(ret == 0);
	return comp;
}

static
const bt_component_sink *create_sink(bt_graph *graph)
{
	const bt_component_sink *comp;
	int ret;

	ret = bt_graph_add_sink_component(graph, sink_comp_class,
		"sink-comp", NULL, &comp);
	BT_ASSERT(ret == 0);
	return comp;
}

static
bt_graph *create_graph(void)
{
	bt_graph *graph = bt_graph_create();
	int ret;

	BT_ASSERT(graph);
	ret = bt_graph_add_source_component_output_port_added_listener(
		graph, graph_src_output_port_added, NULL, NULL, NULL);
	BT_ASSERT(ret >= 0);
	ret = bt_graph_add_sink_component_input_port_added_listener(
		graph, graph_sink_input_port_added, NULL, NULL, NULL);
	BT_ASSERT(ret >= 0);
	ret = bt_graph_add_source_sink_component_ports_connected_listener(
		graph, graph_src_sink_ports_connected, NULL, NULL, NULL);
	BT_ASSERT(ret >= 0);
	return graph;
}

static
void prepare_test(enum test test, const char *name)
{
	clear_events();
	current_test = test;
	diag("test: %s", name);
}

static
void test_src_adds_port_in_port_connected(void)
{
	const bt_component_source *src;
	const bt_component_sink *sink;
	const bt_component *gsrc;
	const bt_component *gsink;
	bt_graph *graph;
	const bt_port_output *src_def_port;
	const bt_port_output *src_hello_port;
	const bt_port_input *sink_def_port;
	const bt_port *gsrc_def_port;
	const bt_port *gsrc_hello_port;
	const bt_port *gsink_def_port;
	struct event event;
	bt_graph_status status;
	size_t src_accept_port_connection_pos;
	size_t sink_accept_port_connection_pos;
	size_t src_port_connected_pos;
	size_t sink_port_connected_pos;
	size_t graph_ports_connected_pos;
	size_t graph_port_added_src_pos;

	prepare_test(TEST_SRC_ADDS_PORT_IN_PORT_CONNECTED,
		"source adds port in port connected");
	graph = create_graph();
	BT_ASSERT(graph);
	src = create_src(graph);
	sink = create_sink(graph);
	src_def_port = bt_component_source_borrow_output_port_by_name_const(src,
									    "out");
	BT_ASSERT(src_def_port);
	sink_def_port = bt_component_sink_borrow_input_port_by_name_const(sink,
									  "in");
	BT_ASSERT(sink_def_port);
	status = bt_graph_connect_ports(graph, src_def_port,
		sink_def_port, NULL);
	BT_ASSERT(status == 0);
	src_hello_port = bt_component_source_borrow_output_port_by_name_const(src,
									      "hello");
	BT_ASSERT(src_hello_port);
	gsrc = bt_component_source_as_component_const(src);
	gsink = bt_component_sink_as_component_const(sink);
	gsrc_def_port = bt_port_output_as_port_const(src_def_port);
	gsrc_hello_port = bt_port_output_as_port_const(src_hello_port);
	gsink_def_port = bt_port_input_as_port_const(sink_def_port);

	/* We're supposed to have 8 events */
	ok(events->len == 8, "we have the expected number of events");

	/* Source's port added */
	event.type = GRAPH_SRC_OUTPUT_PORT_ADDED;
	event.data.graph_src_output_port_added.comp = gsrc;
	event.data.graph_src_output_port_added.port = gsrc_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for source, initial)");

	/* Sink's port added */
	event.type = GRAPH_SINK_INPUT_PORT_ADDED;
	event.data.graph_sink_input_port_added.comp = gsink;
	event.data.graph_sink_input_port_added.port = gsink_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for sink, initial)");

	/* Source's accept port connection */
	event.type = SRC_COMP_ACCEPT_OUTPUT_PORT_CONNECTION;
	event.data.src_comp_accept_output_port_connection.comp = gsrc;
	event.data.src_comp_accept_output_port_connection.self_port = gsrc_def_port;
	event.data.src_comp_accept_output_port_connection.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's accept port connection event");
	src_accept_port_connection_pos = event_pos(&event);

	/* Sink's accept port connection */
	event.type = SINK_COMP_ACCEPT_INPUT_PORT_CONNECTION;
	event.data.sink_comp_accept_input_port_connection.comp = gsink;
	event.data.sink_comp_accept_input_port_connection.self_port = gsink_def_port;
	event.data.sink_comp_accept_input_port_connection.other_port = gsrc_def_port;
	ok(has_event(&event), "got the expected sink's accept port connection event");
	sink_accept_port_connection_pos = event_pos(&event);

	/* Source's port connected */
	event.type = SRC_COMP_OUTPUT_PORT_CONNECTED;
	event.data.src_comp_output_port_connected.comp = gsrc;
	event.data.src_comp_output_port_connected.self_port = gsrc_def_port;
	event.data.src_comp_output_port_connected.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's port connected event");
	src_port_connected_pos = event_pos(&event);

	/* Graph's port added (source) */
	event.type = GRAPH_SRC_OUTPUT_PORT_ADDED;
	event.data.graph_src_output_port_added.comp = gsrc;
	event.data.graph_src_output_port_added.port = gsrc_hello_port;
	ok(has_event(&event), "got the expected graph's port added event (for source)");
	graph_port_added_src_pos = event_pos(&event);

	/* Sink's port connected */
	event.type = SINK_COMP_INPUT_PORT_CONNECTED;
	event.data.sink_comp_input_port_connected.comp = gsink;
	event.data.sink_comp_input_port_connected.self_port = gsink_def_port;
	event.data.sink_comp_input_port_connected.other_port = gsrc_def_port;
	ok(has_event(&event), "got the expected sink's port connected event");
	sink_port_connected_pos = event_pos(&event);

	/* Graph's ports connected */
	event.type = GRAPH_SRC_SINK_PORTS_CONNECTED;
	event.data.graph_src_sink_ports_connected.upstream_comp = gsrc;
	event.data.graph_src_sink_ports_connected.downstream_comp = gsink;
	event.data.graph_src_sink_ports_connected.upstream_port = gsrc_def_port;
	event.data.graph_src_sink_ports_connected.downstream_port = gsink_def_port;
	ok(has_event(&event), "got the expected graph's ports connected event");
	graph_ports_connected_pos = event_pos(&event);

	/* Order of events */
	ok(src_port_connected_pos < graph_ports_connected_pos,
		"event order is good (1)");
	ok(sink_port_connected_pos < graph_ports_connected_pos,
		"event order is good (2)");
	ok(src_accept_port_connection_pos < src_port_connected_pos,
		"event order is good (3)");
	ok(sink_accept_port_connection_pos < sink_port_connected_pos,
		"event order is good (4)");
	ok(src_port_connected_pos < graph_port_added_src_pos,
		"event order is good (5)");
	ok(graph_port_added_src_pos < graph_ports_connected_pos,
		"event order is good (6)");

	bt_component_source_put_ref(src);
	bt_component_sink_put_ref(sink);
	bt_graph_put_ref(graph);
}

static
void test_simple(void)
{
	const bt_component_source *src;
	const bt_component_sink *sink;
	const bt_component *gsrc;
	const bt_component *gsink;
	bt_graph *graph;
	const bt_port_output *src_def_port;
	const bt_port_input *sink_def_port;
	const bt_port *gsrc_def_port;
	const bt_port *gsink_def_port;
	struct event event;
	bt_graph_status status;
	size_t src_accept_port_connection_pos;
	size_t sink_accept_port_connection_pos;
	size_t src_port_connected_pos;
	size_t sink_port_connected_pos;
	size_t graph_ports_connected_pos;

	prepare_test(TEST_SIMPLE, "simple");
	graph = create_graph();
	BT_ASSERT(graph);
	src = create_src(graph);
	sink = create_sink(graph);
	src_def_port = bt_component_source_borrow_output_port_by_name_const(src,
									    "out");
	BT_ASSERT(src_def_port);
	sink_def_port = bt_component_sink_borrow_input_port_by_name_const(sink,
									  "in");
	BT_ASSERT(sink_def_port);
	status = bt_graph_connect_ports(graph, src_def_port,
		sink_def_port, NULL);
	BT_ASSERT(status == 0);
	gsrc = bt_component_source_as_component_const(src);
	gsink = bt_component_sink_as_component_const(sink);
	gsrc_def_port = bt_port_output_as_port_const(src_def_port);
	gsink_def_port = bt_port_input_as_port_const(sink_def_port);

	/* We're supposed to have 7 events */
	ok(events->len == 7, "we have the expected number of events");

	/* Source's port added */
	event.type = GRAPH_SRC_OUTPUT_PORT_ADDED;
	event.data.graph_src_output_port_added.comp = gsrc;
	event.data.graph_src_output_port_added.port = gsrc_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for source, initial)");

	/* Sink's port added */
	event.type = GRAPH_SINK_INPUT_PORT_ADDED;
	event.data.graph_sink_input_port_added.comp = gsink;
	event.data.graph_sink_input_port_added.port = gsink_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for sink, initial)");

	/* Source's accept port connection */
	event.type = SRC_COMP_ACCEPT_OUTPUT_PORT_CONNECTION;
	event.data.src_comp_accept_output_port_connection.comp = gsrc;
	event.data.src_comp_accept_output_port_connection.self_port = gsrc_def_port;
	event.data.src_comp_accept_output_port_connection.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's accept port connection event");
	src_accept_port_connection_pos = event_pos(&event);

	/* Sink's accept port connection */
	event.type = SINK_COMP_ACCEPT_INPUT_PORT_CONNECTION;
	event.data.sink_comp_accept_input_port_connection.comp = gsink;
	event.data.sink_comp_accept_input_port_connection.self_port = gsink_def_port;
	event.data.sink_comp_accept_input_port_connection.other_port = gsrc_def_port;
	ok(has_event(&event), "got the expected sink's accept port connection event");
	sink_accept_port_connection_pos = event_pos(&event);

	/* Source's port connected */
	event.type = SRC_COMP_OUTPUT_PORT_CONNECTED;
	event.data.src_comp_output_port_connected.comp = gsrc;
	event.data.src_comp_output_port_connected.self_port = gsrc_def_port;
	event.data.src_comp_output_port_connected.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's port connected event");
	src_port_connected_pos = event_pos(&event);

	/* Sink's port connected */
	event.type = SINK_COMP_INPUT_PORT_CONNECTED;
	event.data.sink_comp_input_port_connected.comp = gsink;
	event.data.sink_comp_input_port_connected.self_port = gsink_def_port;
	event.data.sink_comp_input_port_connected.other_port = gsrc_def_port;
	ok(has_event(&event), "got the expected sink's port connected event");
	sink_port_connected_pos = event_pos(&event);

	/* Graph's ports connected */
	event.type = GRAPH_SRC_SINK_PORTS_CONNECTED;
	event.data.graph_src_sink_ports_connected.upstream_comp = gsrc;
	event.data.graph_src_sink_ports_connected.downstream_comp = gsink;
	event.data.graph_src_sink_ports_connected.upstream_port = gsrc_def_port;
	event.data.graph_src_sink_ports_connected.downstream_port = gsink_def_port;
	ok(has_event(&event), "got the expected graph's ports connected event");
	graph_ports_connected_pos = event_pos(&event);

	/* Order of events */
	ok(src_port_connected_pos < graph_ports_connected_pos,
		"event order is good (1)");
	ok(sink_port_connected_pos < graph_ports_connected_pos,
		"event order is good (2)");
	ok(src_accept_port_connection_pos < src_port_connected_pos,
		"event order is good (3)");
	ok(sink_accept_port_connection_pos < sink_port_connected_pos,
		"event order is good (4)");

	bt_component_sink_put_ref(sink);
	bt_graph_put_ref(graph);
	bt_component_source_put_ref(src);
}

static
void test_src_port_connected_error(void)
{
	const bt_component_source *src;
	const bt_component_sink *sink;
	const bt_component *gsrc;
	const bt_component *gsink;
	bt_graph *graph;
	const bt_port_output *src_def_port;
	const bt_port_input *sink_def_port;
	const bt_port *gsrc_def_port;
	const bt_port *gsink_def_port;
	const bt_connection *conn = NULL;
	struct event event;
	bt_graph_status status;
	size_t src_accept_port_connection_pos;
	size_t src_port_connected_pos;

	prepare_test(TEST_SRC_PORT_CONNECTED_ERROR, "port connected error: source");
	graph = create_graph();
	BT_ASSERT(graph);
	src = create_src(graph);
	sink = create_sink(graph);
	src_def_port = bt_component_source_borrow_output_port_by_name_const(src,
									    "out");
	BT_ASSERT(src_def_port);
	sink_def_port = bt_component_sink_borrow_input_port_by_name_const(sink,
									  "in");
	BT_ASSERT(sink_def_port);
	status = bt_graph_connect_ports(graph, src_def_port,
		sink_def_port, &conn);
	ok(status != BT_GRAPH_STATUS_OK,
		"bt_graph_connect_ports() returns an error");
	ok(!conn, "returned connection is still NULL");
	gsrc = bt_component_source_as_component_const(src);
	gsink = bt_component_sink_as_component_const(sink);
	gsrc_def_port = bt_port_output_as_port_const(src_def_port);
	gsink_def_port = bt_port_input_as_port_const(sink_def_port);

	/* We're supposed to have 5 events */
	ok(events->len == 5, "we have the expected number of events");

	/* Source's port added */
	event.type = GRAPH_SRC_OUTPUT_PORT_ADDED;
	event.data.graph_src_output_port_added.comp = gsrc;
	event.data.graph_src_output_port_added.port = gsrc_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for source, initial)");

	/* Sink's port added */
	event.type = GRAPH_SINK_INPUT_PORT_ADDED;
	event.data.graph_sink_input_port_added.comp = gsink;
	event.data.graph_sink_input_port_added.port = gsink_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for sink, initial)");

	/* Source's accept port connection */
	event.type = SRC_COMP_ACCEPT_OUTPUT_PORT_CONNECTION;
	event.data.src_comp_accept_output_port_connection.comp = gsrc;
	event.data.src_comp_accept_output_port_connection.self_port = gsrc_def_port;
	event.data.src_comp_accept_output_port_connection.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's accept port connection event");
	src_accept_port_connection_pos = event_pos(&event);

	/* Sink's accept port connection */
	event.type = SINK_COMP_ACCEPT_INPUT_PORT_CONNECTION;
	event.data.sink_comp_accept_input_port_connection.comp = gsink;
	event.data.sink_comp_accept_input_port_connection.self_port = gsink_def_port;
	event.data.sink_comp_accept_input_port_connection.other_port = gsrc_def_port;
	ok(has_event(&event), "got the expected sink's accept port connection event");

	/* Source's port connected */
	event.type = SRC_COMP_OUTPUT_PORT_CONNECTED;
	event.data.src_comp_output_port_connected.comp = gsrc;
	event.data.src_comp_output_port_connected.self_port = gsrc_def_port;
	event.data.src_comp_output_port_connected.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's port connected event");
	src_port_connected_pos = event_pos(&event);

	/* Order of events */
	ok(src_accept_port_connection_pos < src_port_connected_pos,
		"event order is good (1)");

	bt_graph_put_ref(graph);
	bt_component_sink_put_ref(sink);
	bt_component_source_put_ref(src);
	bt_connection_put_ref(conn);
}

static
void test_sink_port_connected_error(void)
{
	const bt_component_source *src;
	const bt_component_sink *sink;
	const bt_component *gsrc;
	const bt_component *gsink;
	bt_graph *graph;
	const bt_port_output *src_def_port;
	const bt_port_input *sink_def_port;
	const bt_port *gsrc_def_port;
	const bt_port *gsink_def_port;
	const bt_connection *conn = NULL;
	struct event event;
	bt_graph_status status;
	size_t src_accept_port_connection_pos;
	size_t sink_accept_port_connection_pos;
	size_t src_port_connected_pos;
	size_t sink_port_connected_pos;

	prepare_test(TEST_SINK_PORT_CONNECTED_ERROR, "port connected error: sink");
	graph = create_graph();
	BT_ASSERT(graph);
	src = create_src(graph);
	sink = create_sink(graph);
	src_def_port = bt_component_source_borrow_output_port_by_name_const(src,
									    "out");
	BT_ASSERT(src_def_port);
	sink_def_port = bt_component_sink_borrow_input_port_by_name_const(sink,
									  "in");
	BT_ASSERT(sink_def_port);
	status = bt_graph_connect_ports(graph, src_def_port,
		sink_def_port, &conn);
	ok(status != BT_GRAPH_STATUS_OK,
		"bt_graph_connect_ports() returns an error");
	ok(!conn, "returned connection is still NULL");
	gsrc = bt_component_source_as_component_const(src);
	gsink = bt_component_sink_as_component_const(sink);
	gsrc_def_port = bt_port_output_as_port_const(src_def_port);
	gsink_def_port = bt_port_input_as_port_const(sink_def_port);

	/* We're supposed to have 6 events */
	ok(events->len == 6, "we have the expected number of events");

	/* Source's port added */
	event.type = GRAPH_SRC_OUTPUT_PORT_ADDED;
	event.data.graph_src_output_port_added.comp = gsrc;
	event.data.graph_src_output_port_added.port = gsrc_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for source, initial)");

	/* Sink's port added */
	event.type = GRAPH_SINK_INPUT_PORT_ADDED;
	event.data.graph_sink_input_port_added.comp = gsink;
	event.data.graph_sink_input_port_added.port = gsink_def_port;
	ok(has_event(&event), "got the expected graph's port added event (for sink, initial)");

	/* Source's accept port connection */
	event.type = SRC_COMP_ACCEPT_OUTPUT_PORT_CONNECTION;
	event.data.src_comp_accept_output_port_connection.comp = gsrc;
	event.data.src_comp_accept_output_port_connection.self_port = gsrc_def_port;
	event.data.src_comp_accept_output_port_connection.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's accept port connection event");
	src_accept_port_connection_pos = event_pos(&event);

	/* Sink's accept port connection */
	event.type = SINK_COMP_ACCEPT_INPUT_PORT_CONNECTION;
	event.data.sink_comp_accept_input_port_connection.comp = gsink;
	event.data.sink_comp_accept_input_port_connection.self_port = gsink_def_port;
	event.data.sink_comp_accept_input_port_connection.other_port = gsrc_def_port;
	ok(has_event(&event), "got the expected sink's accept port connection event");
	sink_accept_port_connection_pos = event_pos(&event);

	/* Source's port connected */
	event.type = SRC_COMP_OUTPUT_PORT_CONNECTED;
	event.data.src_comp_output_port_connected.comp = gsrc;
	event.data.src_comp_output_port_connected.self_port = gsrc_def_port;
	event.data.src_comp_output_port_connected.other_port = gsink_def_port;
	ok(has_event(&event), "got the expected source's port connected event");
	src_port_connected_pos = event_pos(&event);

	/* Sink's port connected */
	event.type = SINK_COMP_INPUT_PORT_CONNECTED;
	event.data.sink_comp_input_port_connected.comp = gsink;
	event.data.sink_comp_input_port_connected.self_port = gsink_def_port;
	event.data.sink_comp_input_port_connected.other_port = gsrc_def_port;
	ok(has_event(&event), "got the expected sink's port connected event");
	sink_port_connected_pos = event_pos(&event);

	/* Order of events */
	ok(src_accept_port_connection_pos < src_port_connected_pos,
		"event order is good (1)");
	ok(sink_accept_port_connection_pos < sink_port_connected_pos,
		"event order is good (2)");

	bt_connection_put_ref(conn);
	bt_graph_put_ref(graph);
	bt_component_sink_put_ref(sink);
	bt_component_source_put_ref(src);
}

static
void test_empty_graph(void)
{
	bt_graph *graph;

	prepare_test(TEST_EMPTY_GRAPH, "empty graph");
	graph = create_graph();
	ok(events->len == 0, "empty graph generates no events");
	bt_graph_put_ref(graph);
}

int main(int argc, char **argv)
{
	plan_tests(NR_TESTS);
	init_test();
	test_empty_graph();
	test_simple();
	test_src_port_connected_error();
	test_sink_port_connected_error();
	test_src_adds_port_in_port_connected();
	fini_test();
	return exit_status();
}
