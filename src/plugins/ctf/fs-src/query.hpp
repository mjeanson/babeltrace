/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * BabelTrace - CTF on File System Component
 */

#ifndef BABELTRACE_PLUGINS_CTF_FS_SRC_QUERY_HPP
#define BABELTRACE_PLUGINS_CTF_FS_SRC_QUERY_HPP

#include "cpp-common/bt2/value.hpp"

namespace bt2c {

class Logger;

} /* namespace bt2c */

bt2::Value::Shared metadata_info_query(bt2::ConstMapValue params, const bt2c::Logger& logger);

bt2::Value::Shared trace_infos_query(bt2::ConstMapValue params, const bt2c::Logger& logger);

bt2::Value::Shared support_info_query(bt2::ConstMapValue params, const bt2c::Logger& logger);

#endif /* BABELTRACE_PLUGINS_CTF_FS_SRC_QUERY_HPP */
