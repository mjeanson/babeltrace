/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022 EfficiOS, Inc.
 */

#include <babeltrace2/babeltrace.h>
#include "common/assert.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <glib.h>

#include "tap/tap.h"

#define NR_TESTS 13

static
bt_component_class_sink_consume_method_status dummy_consume(
		bt_self_component_sink *self_component __attribute__((unused)))
{
	return BT_COMPONENT_CLASS_SINK_CONSUME_METHOD_STATUS_OK;
}

static
bt_component_class *create_cls(const char *name,
		bt_component_class_sink_get_supported_mip_versions_method get_supported_method)
{
	bt_component_class_sink *sink;
	bt_component_class_set_method_status set_method_status;

	sink = bt_component_class_sink_create(name, dummy_consume);
	BT_ASSERT(sink);

	set_method_status =
		bt_component_class_sink_set_get_supported_mip_versions_method(
			sink, get_supported_method);
	BT_ASSERT(set_method_status == BT_COMPONENT_CLASS_SET_METHOD_STATUS_OK);

	return bt_component_class_sink_as_component_class(sink);
}

static
bt_component_class_get_supported_mip_versions_method_status
get_supported_contains_non_existent(
		bt_self_component_class_sink *source_component_class __attribute__((unused)),
		const bt_value *params __attribute__((unused)),
		void *initialize_method_data __attribute__((unused)),
		bt_logging_level logging_level __attribute__((unused)),
		bt_integer_range_set_unsigned *supported_versions)
{
	bt_integer_range_set_unsigned_add_range(supported_versions,
		0, 0xfffffffffff);
	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}

static
bt_component_class_get_supported_mip_versions_method_status
get_supported_only_non_existent(
		bt_self_component_class_sink *source_component_class __attribute__((unused)),
		const bt_value *params __attribute__((unused)),
		void *initialize_method_data __attribute__((unused)),
		bt_logging_level logging_level __attribute__((unused)),
		bt_integer_range_set_unsigned *supported_versions)
{
	bt_integer_range_set_unsigned_add_range(supported_versions,
		0xffffffffff0, 0xfffffffffff);
	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}

static
bt_component_class_get_supported_mip_versions_method_status
get_supported_00(
		bt_self_component_class_sink *source_component_class __attribute__((unused)),
		const bt_value *params __attribute__((unused)),
		void *initialize_method_data __attribute__((unused)),
		bt_logging_level logging_level __attribute__((unused)),
		bt_integer_range_set_unsigned *supported_versions)
{
	bt_integer_range_set_unsigned_add_range(supported_versions,
		0, 0);
	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}

static
bt_component_class_get_supported_mip_versions_method_status
get_supported_01(
		bt_self_component_class_sink *source_component_class __attribute__((unused)),
		const bt_value *params __attribute__((unused)),
		void *initialize_method_data __attribute__((unused)),
		bt_logging_level logging_level __attribute__((unused)),
		bt_integer_range_set_unsigned *supported_versions)
{
	bt_integer_range_set_unsigned_add_range(supported_versions,
		0, 1);
	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}


static
bt_component_class_get_supported_mip_versions_method_status
get_supported_11(
		bt_self_component_class_sink *source_component_class __attribute__((unused)),
		const bt_value *params __attribute__((unused)),
		void *initialize_method_data __attribute__((unused)),
		bt_logging_level logging_level __attribute__((unused)),
		bt_integer_range_set_unsigned *supported_versions)
{
	bt_integer_range_set_unsigned_add_range(supported_versions,
		1, 1);
	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}

static
bt_component_class_get_supported_mip_versions_method_status
get_supported_error(
		bt_self_component_class_sink *source_component_class __attribute__((unused)),
		const bt_value *params __attribute__((unused)),
		void *initialize_method_data __attribute__((unused)),
		bt_logging_level logging_level __attribute__((unused)),
		bt_integer_range_set_unsigned *supported_versions __attribute__((unused)))
{
	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_ERROR;
}

static
void add_descr(bt_component_descriptor_set *descrs, bt_component_class *cls)
{
	bt_component_descriptor_set_add_descriptor_status status =
		bt_component_descriptor_set_add_descriptor(descrs, cls, NULL);
	BT_ASSERT(status == BT_COMPONENT_DESCRIPTOR_SET_ADD_DESCRIPTOR_STATUS_OK);
}

static
void test_common(
		bt_component_class_sink_get_supported_mip_versions_method get_supported_a,
		bt_component_class_sink_get_supported_mip_versions_method get_supported_b,
		bt_get_greatest_operative_mip_version_status expected_status,
		uint64_t expected_mip_version)
{
	bt_component_descriptor_set *descrs;
	uint64_t mip_version;
	bt_get_greatest_operative_mip_version_status status;
	bt_component_class *cls_a = create_cls("cls_a", get_supported_a);
	bt_component_class *cls_b = create_cls("cls_b", get_supported_b);

	descrs = bt_component_descriptor_set_create();
	BT_ASSERT(descrs);

	add_descr(descrs, cls_a);
	add_descr(descrs, cls_b);

	status = bt_get_greatest_operative_mip_version(descrs,
		BT_LOGGING_LEVEL_INFO, &mip_version);
	ok(status == expected_status, "status is as expected");

	if (expected_status == BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_OK) {
		ok(mip_version == expected_mip_version, "MIP version is as expected");
	}

	bt_component_class_put_ref(cls_a);
	bt_component_class_put_ref(cls_b);
	bt_component_descriptor_set_put_ref(descrs);
}

static
void test_ok(bt_component_class_sink_get_supported_mip_versions_method get_supported_a,
		bt_component_class_sink_get_supported_mip_versions_method get_supported_b,
		uint64_t expected_mip_version)
{
	test_common(get_supported_a, get_supported_b,
		BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_OK,
		expected_mip_version);
}

static
void test_no_match(bt_component_class_sink_get_supported_mip_versions_method get_supported_a,
		bt_component_class_sink_get_supported_mip_versions_method get_supported_b)
{
	test_common(get_supported_a, get_supported_b,
		BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_NO_MATCH, 0);
}

static
void test_error(bt_component_class_sink_get_supported_mip_versions_method get_supported_a,
		bt_component_class_sink_get_supported_mip_versions_method get_supported_b)
{
	test_common(get_supported_a, get_supported_b,
		BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_ERROR, 0);
}

int main(void)
{
	plan_tests(NR_TESTS);

	test_no_match(get_supported_00, get_supported_only_non_existent);
	test_no_match(get_supported_00, get_supported_11);

	test_ok(get_supported_00, get_supported_contains_non_existent, 0);
	test_ok(get_supported_00, get_supported_00, 0);
	test_ok(get_supported_00, get_supported_01, 0);
	test_ok(get_supported_01, get_supported_01, 1);
	test_ok(get_supported_01, get_supported_11, 1);

	test_error(get_supported_01, get_supported_error);

	return exit_status();
}
