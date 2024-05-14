/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_LOGGING_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_LOGGING_HPP

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/logging.hpp"

#define _BT_CPPLOGT_LINENO(logger, _lineno, _msg, args...)                                         \
    BT_CPPLOGT_SPEC((logger), "At line {} in metadata stream: " _msg, _lineno, ##args)

#define _BT_CPPLOGW_LINENO(logger, _lineno, _msg, args...)                                         \
    BT_CPPLOGW_SPEC((logger), "At line {} in metadata stream: " _msg, _lineno, ##args)

#define _BT_CPPLOGE_LINENO(logger, _lineno, _msg, args...)                                         \
    BT_CPPLOGE_SPEC((logger), "At line {} in metadata stream: " _msg, _lineno, ##args)

#define _BT_CPPLOGE_APPEND_CAUSE_LINENO(logger, _lineno, _msg, args...)                            \
    BT_CPPLOGE_APPEND_CAUSE_SPEC((logger), "At line {} in metadata stream: " _msg, _lineno, ##args)

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_LOGGING_HPP */
