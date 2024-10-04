/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2024 EfficiOS, Inc.
 */

#ifndef BABELTRACE_CLOCK_CORRELATION_VALIDATOR_CLOCK_CORRELATION_VALIDATOR_H
#define BABELTRACE_CLOCK_CORRELATION_VALIDATOR_CLOCK_CORRELATION_VALIDATOR_H

#include <glib.h>
#include <stdbool.h>
#include <babeltrace2/babeltrace.h>

#include "common/macros.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bt_clock_class;
struct bt_message;

enum bt_clock_correlation_validator_error_type
{
	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_NO_CLOCK_CLASS_GOT_ONE,

	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_KNOWN_GOT_NO_CLOCK_CLASS,
	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_KNOWN_GOT_UNKNOWN_ORIGIN,
	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_KNOWN_GOT_OTHER_ORIGIN,

	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_ID_GOT_NO_CLOCK_CLASS,
	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_ID_GOT_KNOWN_ORIGIN,
	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_ID_GOT_WITHOUT_ID,
	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_ID_GOT_OTHER_ID,

	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITHOUT_ID_GOT_NO_CLOCK_CLASS,
	BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITHOUT_ID_GOT_OTHER_CLOCK_CLASS,
};

struct bt_clock_correlation_validator *bt_clock_correlation_validator_create(
	void) BT_NOEXCEPT;

bool bt_clock_correlation_validator_validate_message(
	struct bt_clock_correlation_validator *validator,
	const struct bt_message *msg,
	uint64_t graph_mip_version,
	enum bt_clock_correlation_validator_error_type *type,
	const struct bt_clock_class ** const actual_clock_cls,
	const struct bt_clock_class ** const ref_clock_cls) BT_NOEXCEPT;

void bt_clock_correlation_validator_destroy(
	struct bt_clock_correlation_validator *validator) BT_NOEXCEPT;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BABELTRACE_CLOCK_CORRELATION_VALIDATOR_CLOCK_CORRELATION_VALIDATOR_H */
