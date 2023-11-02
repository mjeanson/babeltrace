/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_FS_METADATA_H
#define CTF_FS_METADATA_H

#include <stdio.h>

#include <babeltrace2/babeltrace.h>

namespace bt2c {

class Logger;

} /* namespace bt2c */

#include "../common/src/clk-cls-cfg.hpp"

#define CTF_FS_METADATA_FILENAME "metadata"

int ctf_fs_metadata_set_trace_class(bt_self_component *self_comp, struct ctf_fs_trace *ctf_fs_trace,
                                    const ctf::src::ClkClsCfg& clkClsCfg);

FILE *ctf_fs_metadata_open_file(const char *trace_path, const bt2c::Logger& logger);

bool ctf_metadata_is_packetized(FILE *fp, int *byte_order);

#endif /* CTF_FS_METADATA_H */
