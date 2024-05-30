/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_META_CONFIGURE_IR_TRACE_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_META_CONFIGURE_IR_TRACE_HPP

#include <cstdint>

#include "../ctf-ir.hpp"

namespace bt2c {

class Logger;

} /* namespace bt2c */

void ctf_trace_class_configure_ir_trace(struct ctf_trace_class *tc, bt2::Trace ir_trace);

void ctf_trace_class_configure_ir_trace(const ctf::src::TraceCls& tc, bt2::Trace irTrace,
                                        std::uint64_t mipVersion, const bt2c::Logger& parentLogger);

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_CTF_META_CONFIGURE_IR_TRACE_HPP */
