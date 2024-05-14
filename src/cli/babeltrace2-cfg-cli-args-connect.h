/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_CLI_BABELTRACE2_CFG_CLI_ARGS_CONNECT_H
#define BABELTRACE_CLI_BABELTRACE2_CFG_CLI_ARGS_CONNECT_H

#include <stdlib.h>
#include <stdint.h>
#include <glib.h>
#include "babeltrace2-cfg.h"

int bt_config_cli_args_create_connections(struct bt_config *cfg,
		const bt_value *connection_args,
		char *error_buf, size_t error_buf_size);

#endif /* BABELTRACE_CLI_BABELTRACE2_CFG_CLI_ARGS_CONNECT_H */
