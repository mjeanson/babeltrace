/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_TEXT_DMESG_DMESG_H
#define BABELTRACE_PLUGINS_TEXT_DMESG_DMESG_H

#include <stdbool.h>
#include "common/macros.h"
#include <babeltrace2/babeltrace.h>

bt_component_class_get_supported_mip_versions_method_status
dmesg_supported_mip_versions(bt_self_component_class_source *self_component_class,
		const bt_value *params, void *initialize_method_data,
		bt_logging_level logging_level,
		bt_integer_range_set_unsigned *supported_versions);

bt_component_class_initialize_method_status dmesg_init(
		bt_self_component_source *self_comp,
		bt_self_component_source_configuration *config,
		const bt_value *params, void *init_method_data);

void dmesg_finalize(bt_self_component_source *self_comp);

bt_message_iterator_class_initialize_method_status dmesg_msg_iter_init(
		bt_self_message_iterator *self_msg_iter,
		bt_self_message_iterator_configuration *config,
		bt_self_component_port_output *self_port);

void dmesg_msg_iter_finalize(
		bt_self_message_iterator *self_msg_iter);

bt_message_iterator_class_next_method_status dmesg_msg_iter_next(
		bt_self_message_iterator *self_msg_iter,
		bt_message_array_const msgs, uint64_t capacity,
		uint64_t *count);

bt_message_iterator_class_can_seek_beginning_method_status
dmesg_msg_iter_can_seek_beginning(
		bt_self_message_iterator *message_iterator, bt_bool *can_seek);

bt_message_iterator_class_seek_beginning_method_status dmesg_msg_iter_seek_beginning(
		bt_self_message_iterator *message_iterator);

#endif /* BABELTRACE_PLUGINS_TEXT_DMESG_DMESG_H */
