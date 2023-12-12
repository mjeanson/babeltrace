/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * BabelTrace - CTF on File System Component
 */

#ifndef BABELTRACE_PLUGIN_CTF_FS_QUERY_H
#define BABELTRACE_PLUGIN_CTF_FS_QUERY_H

#include "cpp-common/bt2/value.hpp"

namespace bt2c {

class Logger;

} /* namespace bt2c */

bt2::Value::Shared metadata_info_query(bt2::ConstMapValue params, const bt2c::Logger& logger);

bt2::Value::Shared trace_infos_query(bt2::ConstMapValue params, const bt2c::Logger& logger);

bt2::Value::Shared support_info_query(bt2::ConstMapValue params, const bt2c::Logger& logger);

#endif /* BABELTRACE_PLUGIN_CTF_FS_QUERY_H */
