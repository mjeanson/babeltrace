/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_COMMON_MUXING_MUXING_HPP
#define BABELTRACE_PLUGINS_COMMON_MUXING_MUXING_HPP

#include <babeltrace2/babeltrace.h>

#include "common/macros.h"

BT_EXTERN_C int common_muxing_compare_messages(const bt_message *left_msg,
                                               const bt_message *right_msg);

#endif /* BABELTRACE_PLUGINS_COMMON_MUXING_MUXING_HPP */
