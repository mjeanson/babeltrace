/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2018 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_META_VISITORS_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_META_VISITORS_HPP

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/optional-borrowed-object.hpp"
#include "cpp-common/bt2/self-component-port.hpp"

#include "ctf-meta.hpp"

namespace bt2c {

class Logger;

} /* namespace bt2c */

int ctf_trace_class_resolve_field_classes(struct ctf_trace_class *tc,
                                          const bt2c::Logger& parentLogger);

int ctf_trace_class_translate(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                              bt_trace_class *ir_tc, struct ctf_trace_class *tc);

int ctf_trace_class_update_default_clock_classes(struct ctf_trace_class *ctf_tc,
                                                 const bt2c::Logger& parentLogger);

int ctf_trace_class_update_in_ir(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_update_meanings(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_update_text_array_sequence(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_update_alignments(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_update_value_storing_indexes(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_update_stream_class_config(struct ctf_trace_class *ctf_tc);

int ctf_trace_class_validate(struct ctf_trace_class *ctf_tc, const bt2c::Logger& parentLogger);

void ctf_trace_class_warn_meaningless_header_fields(struct ctf_trace_class *ctf_tc,
                                                    const bt2c::Logger& parentLogger);

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_META_VISITORS_HPP */
