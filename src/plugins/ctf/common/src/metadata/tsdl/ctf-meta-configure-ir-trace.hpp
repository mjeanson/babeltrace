/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef _CTF_META_CONFIGURE_IR_TRACE_H
#define _CTF_META_CONFIGURE_IR_TRACE_H

#include "cpp-common/bt2/trace-ir.hpp"

void ctf_trace_class_configure_ir_trace(struct ctf_trace_class *tc, bt2::Trace ir_trace);

#endif /* _CTF_META_CONFIGURE_IR_TRACE_H */
