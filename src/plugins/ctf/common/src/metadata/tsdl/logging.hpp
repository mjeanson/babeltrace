/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef CTF_METADATA_LOGGING_H
#define CTF_METADATA_LOGGING_H

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

#endif /* CTF_METADATA_LOGGING_H */
