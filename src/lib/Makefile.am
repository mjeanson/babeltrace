# SPDX-License-Identifier: MIT

AUTOMAKE_OPTIONS = subdir-objects

# Convenience libraries
noinst_LTLIBRARIES = \
	libgraph.la \
	libplugin.la \
	libprio-heap.la \
	libtrace-ir.la

libgraph_la_SOURCES = \
	graph/message/discarded-items.c \
	graph/message/discarded-items.h \
	graph/message/event.c \
	graph/message/event.h \
	graph/message/iterator.h \
	graph/message/message.c \
	graph/message/message.h \
	graph/message/message-iterator-inactivity.c \
	graph/message/message-iterator-inactivity.h \
	graph/message/packet.c \
	graph/message/packet.h \
	graph/message/stream.c \
	graph/message/stream.h \
	graph/component-class-sink-simple.c \
	graph/component-class-sink-simple.h \
	graph/component-class.c \
	graph/component-class.h \
	graph/component-descriptor-set.c \
	graph/component-descriptor-set.h \
	graph/component-filter.c \
	graph/component-filter.h \
	graph/component-sink.c \
	graph/component-sink.h \
	graph/component-source.c \
	graph/component-source.h \
	graph/component.c \
	graph/component.h \
	graph/connection.c \
	graph/connection.h \
	graph/graph.c \
	graph/graph.h \
	graph/interrupter.c \
	graph/interrupter.h \
	graph/iterator.c \
	graph/message-iterator-class.c \
	graph/message-iterator-class.h \
	graph/mip.c \
	graph/port.c \
	graph/port.h \
	graph/query-executor.c \
	graph/query-executor.h

# Plug-in system library
libplugin_la_SOURCES = \
	plugin/plugin.c \
	plugin/plugin.h \
	plugin/plugin-so.c \
	plugin/plugin-so.h

libplugin_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	'-DBABELTRACE_PLUGIN_PROVIDERS_DIR="$(BABELTRACE_PLUGIN_PROVIDERS_DIR)"'

libprio_heap_la_SOURCES = \
	prio-heap/prio-heap.c \
	prio-heap/prio-heap.h

libtrace_ir_la_SOURCES = \
	trace-ir/attributes.c \
	trace-ir/attributes.h \
	trace-ir/clock-class.c \
	trace-ir/clock-class.h \
	trace-ir/clock-snapshot.c \
	trace-ir/clock-snapshot.h \
	trace-ir/event.c \
	trace-ir/event-class.c \
	trace-ir/event-class.h \
	trace-ir/event.h \
	trace-ir/field.c \
	trace-ir/field-class.c \
	trace-ir/field-class.h \
	trace-ir/field.h \
	trace-ir/field-path.c \
	trace-ir/field-path.h \
	trace-ir/field-wrapper.c \
	trace-ir/field-wrapper.h \
	trace-ir/packet.c \
	trace-ir/packet.h \
	trace-ir/resolve-field-path.c \
	trace-ir/resolve-field-path.h \
	trace-ir/stream.c \
	trace-ir/stream-class.c \
	trace-ir/stream-class.h \
	trace-ir/stream.h \
	trace-ir/trace.c \
	trace-ir/trace-class.c \
	trace-ir/trace-class.h \
	trace-ir/trace.h \
	trace-ir/utils.c \
	trace-ir/utils.h


lib_LTLIBRARIES = libbabeltrace2.la

libbabeltrace2_la_SOURCES = \
	assert-cond-base.h \
	assert-cond.h \
	assert-cond.c \
	babeltrace2.c \
	current-thread.c \
	error.c \
	error.h \
	func-status.h \
	integer-range-set.c \
	integer-range-set.h \
	lib-logging.c \
	logging.c \
	logging.h \
	object-pool.c \
	object-pool.h \
	object.h \
	property.h \
	util.c \
	value.c \
	value.h

libbabeltrace2_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LT_NO_UNDEFINED) \
	-version-info $(BABELTRACE_LIBRARY_VERSION)

libbabeltrace2_la_LIBADD = \
	libprio-heap.la \
	libgraph.la \
	libplugin.la \
	libtrace-ir.la \
	$(top_builddir)/src/logging/libbabeltrace2-logging.la \
	$(top_builddir)/src/libcommon.la \
	$(top_builddir)/src/compat/libcompat.la

if ENABLE_BUILT_IN_PYTHON_PLUGIN_SUPPORT
libbabeltrace2_la_LIBADD += $(top_builddir)/src/python-plugin-provider/babeltrace2-python-plugin-provider.la
endif
