/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_FS_SRC_METADATA_HPP
#define BABELTRACE_PLUGINS_CTF_FS_SRC_METADATA_HPP

#include <stdio.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2/optional-borrowed-object.hpp"
#include "cpp-common/bt2/self-component-port.hpp"

namespace bt2c {

class Logger;

} /* namespace bt2c */

#include "../common/src/clk-cls-cfg.hpp"

#define CTF_FS_METADATA_FILENAME "metadata"

int ctf_fs_metadata_set_trace_class(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                                    struct ctf_fs_trace *ctf_fs_trace,
                                    const ctf::src::ClkClsCfg& clkClsCfg);

FILE *ctf_fs_metadata_open_file(const char *trace_path, const bt2c::Logger& logger);

bool ctf_metadata_is_packetized(FILE *fp, int *byte_order);

#endif /* BABELTRACE_PLUGINS_CTF_FS_SRC_METADATA_HPP */
