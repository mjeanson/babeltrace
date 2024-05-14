/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Babeltrace Trace Converter - Default Configuration
 */

#ifndef BABELTRACE_CLI_BABELTRACE2_CFG_CLI_ARGS_DEFAULT_H
#define BABELTRACE_CLI_BABELTRACE2_CFG_CLI_ARGS_DEFAULT_H

#include "babeltrace2-cfg.h"

enum bt_config_cli_args_status bt_config_cli_args_create_with_default(int argc,
		const char *argv[], struct bt_config **cfg,
		const bt_interrupter *interrupter);

#endif /* BABELTRACE_CLI_BABELTRACE2_CFG_CLI_ARGS_DEFAULT_H */
