/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2018 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_LIB_TRACE_IR_RESOLVE_FIELD_XREF_H
#define BABELTRACE_LIB_TRACE_IR_RESOLVE_FIELD_XREF_H

#include "lib/func-status.h"

struct bt_resolve_field_xref_context {
	struct bt_field_class *packet_context;
	struct bt_field_class *event_common_context;
	struct bt_field_class *event_specific_context;
	struct bt_field_class *event_payload;
};

#endif /* BABELTRACE_LIB_TRACE_IR_RESOLVE_FIELD_XREF_H */
