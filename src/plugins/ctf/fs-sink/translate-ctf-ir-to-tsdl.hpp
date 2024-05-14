/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_FS_SINK_TRANSLATE_CTF_IR_TO_TSDL_HPP
#define BABELTRACE_PLUGINS_CTF_FS_SINK_TRANSLATE_CTF_IR_TO_TSDL_HPP

#include <glib.h>

void translate_trace_ctf_ir_to_tsdl(struct fs_sink_ctf_trace *trace, GString *tsdl);

#endif /* BABELTRACE_PLUGINS_CTF_FS_SINK_TRANSLATE_CTF_IR_TO_TSDL_HPP */
