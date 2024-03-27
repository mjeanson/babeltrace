/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#define BT_LOG_TAG "LIB/MIP"
#include "lib/logging.h"

#include "lib/assert-cond.h"
#include <stdbool.h>
#include <unistd.h>
#include <glib.h>
#include <babeltrace2/graph/graph.h>

#include "common/assert.h"
#include "compat/compiler.h"
#include "common/common.h"
#include "lib/func-status.h"
#include "lib/graph/component-class.h"
#include "lib/value.h"
#include "component-descriptor-set.h"
#include "lib/integer-range-set.h"

#define MAX_MIP_VERSION 1

static
bool unsigned_integer_range_set_contains(
		const struct bt_integer_range_set *range_set, uint64_t value)
{
	bool contains = false;
	uint64_t i;

	BT_ASSERT(range_set);

	for (i = 0; i < range_set->ranges->len; i++) {
		const struct bt_integer_range *range =
			BT_INTEGER_RANGE_SET_RANGE_AT_INDEX(range_set, i);

		if (value >= range->lower.u && value <= range->upper.u) {
			contains = true;
			goto end;
		}
	}

end:
	return contains;
}

/*
 * Log the MIP versions (in `range_set`) supported by the component described by
 * `descr`.
 */
static
void log_supported_mip_versions_range_set(const bt_integer_range_set_unsigned *range_set,
		const struct bt_component_descriptor_set_entry *descr)
{
	uint64_t range_count;
	uint64_t i;

	if (!BT_LOG_ON_DEBUG) {
		goto end;
	}

	range_count = bt_integer_range_set_get_range_count(
		bt_integer_range_set_unsigned_as_range_set_const(range_set));

	BT_LIB_LOGD("Supported MIP version ranges: %![cc-]C", descr->comp_cls);

	for (i = 0; i < range_count; ++i) {
		const bt_integer_range_unsigned *range =
			bt_integer_range_set_unsigned_borrow_range_by_index_const(
				range_set, i);
		uint64_t lower = bt_integer_range_unsigned_get_lower(range);
		uint64_t upper = bt_integer_range_unsigned_get_upper(range);

		BT_LIB_LOGD("  [%" PRIu64 ", %" PRIu64 "]", lower, upper);
	}

end:
	return;
}

/*
 * Get the MIP version ranges supported by descriptors in `descriptors`, append
 * them to `supported_ranges`.
 *
 * The elements of `descriptors` are `struct bt_component_descriptor_set_entry *`.
 * The elements of `supported_ranges` are `bt_integer_range_set_unsigned *`.
 */
static
int get_supported_mip_version_ranges(GPtrArray *descriptors,
		GPtrArray *supported_ranges,
		enum bt_logging_level log_level)
{
	typedef bt_component_class_get_supported_mip_versions_method_status
		(*method_t)(
			void * /* component class */,
			const struct bt_value *,
			void * /* init method data */,
			enum bt_logging_level,
			bt_integer_range_set_unsigned *);

	int status;
	uint64_t i;
	struct bt_integer_range_set_unsigned *range_set = NULL;

	for (i = 0; i < descriptors->len; i++) {
		struct bt_component_descriptor_set_entry *descr =
			descriptors->pdata[i];
		method_t method = NULL;
		const char *method_name = NULL;
		bt_component_class_get_supported_mip_versions_method_status method_status;

		switch (descr->comp_cls->type) {
		case BT_COMPONENT_CLASS_TYPE_SOURCE:
		{
			struct bt_component_class_source *src_cc = (void *)
				descr->comp_cls;

			method = (method_t) src_cc->methods.get_supported_mip_versions;
			method_name = "bt_component_class_source_get_supported_mip_versions_method";
			break;
		}
		case BT_COMPONENT_CLASS_TYPE_FILTER:
		{
			struct bt_component_class_filter *flt_cc = (void *)
				descr->comp_cls;

			method = (method_t) flt_cc->methods.get_supported_mip_versions;
			method_name = "bt_component_class_filter_get_supported_mip_versions_method";
			break;
		}
		case BT_COMPONENT_CLASS_TYPE_SINK:
		{
			struct bt_component_class_sink *sink_cc = (void *)
				descr->comp_cls;

			method = (method_t) sink_cc->methods.get_supported_mip_versions;
			method_name = "bt_component_class_sink_get_supported_mip_versions_method";
			break;
		}
		default:
			bt_common_abort();
		}

		range_set = bt_integer_range_set_unsigned_create();
		if (!range_set) {
			status = BT_FUNC_STATUS_MEMORY_ERROR;
			goto end;
		}

		if (method) {
			BT_ASSERT(descr->params);
			BT_LIB_LOGD("Calling user's \"get supported MIP versions\" method: "
				"%![cc-]+C, %![params-]+v, init-method-data=%p, "
				"log-level=%s",
				descr->comp_cls, descr->params,
				descr->init_method_data,
				bt_common_logging_level_string(log_level));
			method_status = method(descr->comp_cls, descr->params,
				descr->init_method_data, log_level,
				range_set);
			BT_LIB_LOGD("User method returned: status=%s",
				bt_common_func_status_string(method_status));
			BT_ASSERT_POST(method_name, "status-ok-with-at-least-one-range",
				method_status != BT_FUNC_STATUS_OK ||
				bt_integer_range_set_get_range_count(
					bt_integer_range_set_unsigned_as_range_set_const(range_set)) > 0,
				"User method returned `BT_FUNC_STATUS_OK` without "
				"adding a range to the supported MIP version range set.");
			BT_ASSERT_POST_NO_ERROR_IF_NO_ERROR_STATUS(method_name,
				method_status);
			if (method_status < 0) {
				BT_LIB_LOGW_APPEND_CAUSE(
					"Component class's \"get supported MIP versions\" method failed: "
					"%![cc-]+C, %![params-]+v, init-method-data=%p, "
					"log-level=%s",
					descr->comp_cls, descr->params,
					descr->init_method_data,
					bt_common_logging_level_string(log_level));
				status = (int) method_status;
				goto end;
			}
		} else {
			/*
			 * Component class does not implement the
			 * get_supported_mip_versions method, it means it only
			 * supports version 0.
			 */
			bt_integer_range_set_add_range_status add_range_status
				= bt_integer_range_set_unsigned_add_range(range_set, 0, 0);
			if (add_range_status != BT_INTEGER_RANGE_SET_ADD_RANGE_STATUS_OK) {
				status = (int) add_range_status;
				goto end;
			}
		}

		log_supported_mip_versions_range_set(range_set, descr);

		/* Transfer ownership of `range_set` */
		g_ptr_array_add(supported_ranges, range_set);
		range_set = NULL;
	}

	status = BT_FUNC_STATUS_OK;

end:
	bt_object_put_ref(range_set);
	return status;
}

/*
 * Given `supported_ranges`, an array of `bt_integer_range_set_unsigned *`
 * representing the supported MIP version ranges of multiple eventual
 * components, find the greatest version supported by all.
 */
static
bt_get_greatest_operative_mip_version_status find_greatest_compatible_mip_version(
		const GPtrArray *supported_ranges,
		const bt_integer_range_set_unsigned *mip_version_restriction,
		uint64_t *operative_mip_version)
{
	bool versions[MAX_MIP_VERSION + 1];
	guint range_set_i;
	int v;
	bt_get_greatest_operative_mip_version_status status;

	/* Start by assuming all existing MIP versions are supported. */
	for (v = 0; v <= MAX_MIP_VERSION; ++v) {
		versions[v] = true;
	}

	/*
	 * Disable specific versions based on `mip_version_restriction`,
	 * if set.
	 */
	if (mip_version_restriction) {
		for (v = 0; v <= MAX_MIP_VERSION; ++v) {
			if (!unsigned_integer_range_set_contains(
					bt_integer_range_set_unsigned_as_range_set_const(
						mip_version_restriction), v)) {
				versions[v] = false;
			}
		}
	}

	/*
	 * Go over each (soon-to-be) component's range set of support MIP
	 * versions.
	 */
	for (range_set_i = 0; range_set_i < supported_ranges->len; ++range_set_i) {
		const struct bt_integer_range_set *range_set =
			supported_ranges->pdata[range_set_i];
		uint64_t i;

		/*
		 * For each existing MIP version, clear the flag if that
		 * component would not support it.
		 */
		for (i = 0; i <= MAX_MIP_VERSION; ++i) {
			if (!unsigned_integer_range_set_contains(range_set, i)) {
				versions[i] = false;
			}
		}
	}

	/* Find the greatest MIP version with the flag still set. */
	for (v = MAX_MIP_VERSION; v >= 0; --v) {
		if (versions[v]) {
			*operative_mip_version = v;
			status = BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_OK;
			goto end;
		}
	}

	status = BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_NO_MATCH;
end:
	return status;
}

BT_EXPORT
enum bt_get_greatest_operative_mip_version_status
bt_get_greatest_operative_mip_version_with_restriction(
		const struct bt_component_descriptor_set *comp_descr_set,
		enum bt_logging_level log_level,
		const bt_integer_range_set_unsigned *mip_version_restriction,
		uint64_t *mip_version)
{
	int status;
	GPtrArray *supported_ranges;
	unsigned int comp_count =
		comp_descr_set->sources->len +
		comp_descr_set->filters->len +
		comp_descr_set->sinks->len;

	BT_ASSERT_PRE_NO_ERROR();
	BT_ASSERT_PRE_COMP_DESCR_SET_NON_NULL(comp_descr_set);
	BT_ASSERT_PRE_NON_NULL("operative-mip-version-output",
		mip_version,
		"Operative MIP version (output)");
	BT_ASSERT_PRE("component-descriptor-set-is-not-empty",
		comp_count > 0,
		"Component descriptor set is empty: addr=%p", comp_descr_set);

	supported_ranges = g_ptr_array_new_with_free_func(
		(void *) bt_integer_range_set_unsigned_put_ref);
	if (!supported_ranges) {
		BT_CURRENT_THREAD_ERROR_APPEND_CAUSE_FROM_UNKNOWN("Get greatest MIP",
			"Failed to allocate one GPtrArray");
		status = BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_MEMORY_ERROR;
		goto end;
	}

	status = get_supported_mip_version_ranges(
		comp_descr_set->sources, supported_ranges, log_level);
	if (status) {
		goto end;
	}

	status = get_supported_mip_version_ranges(
		comp_descr_set->filters, supported_ranges, log_level);
	if (status) {
		goto end;
	}

	status = get_supported_mip_version_ranges(
		comp_descr_set->sinks, supported_ranges, log_level);
	if (status) {
		goto end;
	}

	status = find_greatest_compatible_mip_version(
		supported_ranges, mip_version_restriction, mip_version);
	if (status == BT_GET_GREATEST_OPERATIVE_MIP_VERSION_STATUS_OK) {
		BT_LIB_LOGD("Found a compatible MIP version: version=%d",
			*mip_version);
	} else {
		BT_LIB_LOGD("Failed to find a compatible MIP version: status=%s",
			bt_common_func_status_string(status));
	}

end:
	g_ptr_array_free(supported_ranges, TRUE);
	return status;
}

BT_EXPORT
enum bt_get_greatest_operative_mip_version_status
bt_get_greatest_operative_mip_version(
		const struct bt_component_descriptor_set *comp_descr_set,
		enum bt_logging_level log_level,
		uint64_t *mip_version)
{
	return bt_get_greatest_operative_mip_version_with_restriction(
				comp_descr_set, log_level, NULL, mip_version);
}

BT_EXPORT
uint64_t bt_get_maximal_mip_version(void)
{
	return MAX_MIP_VERSION;
}
