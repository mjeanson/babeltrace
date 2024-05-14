/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2019 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PARAM_PARSE_PARAM_PARSE_H
#define BABELTRACE_PARAM_PARSE_PARAM_PARSE_H

#include <babeltrace2/babeltrace.h>

#include <glib.h>

#include "common/macros.h"

bt_value *bt_param_parse(const char *arg, GString *ini_error);

#endif /* BABELTRACE_PARAM_PARSE_PARAM_PARSE_H */
