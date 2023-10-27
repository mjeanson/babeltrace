/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2022 EfficiOS Inc. and Linux Foundation
 */

#define BT_LOG_TAG "LIB/FIELD-LOCATION"
#include "lib/logging.h"
#include "lib/assert-cond.h"
#include "lib/object.h"
#include "lib/graph/graph.h"
#include "lib/trace-ir/trace-class.h"
#include "compat/compiler.h"

#include "field-location.h"

static
void destroy_field_location(bt_object *object)
{
	struct bt_field_location *field_location =
		(struct bt_field_location *) object;

	if (field_location->items) {
		g_ptr_array_free(field_location->items, TRUE);
	}

	g_free(field_location);
}

BT_EXPORT
bt_field_location *bt_field_location_create(
		bt_trace_class *trace_class,
		bt_field_location_scope scope,
		const char *const *items,
		uint64_t item_count)
{
	struct bt_field_location *field_location = NULL;
	uint64_t i;

	BT_LOGD_STR("Creating field location object.");

	BT_ASSERT_PRE_TC_MIP_VERSION_GE(trace_class, 1);
	BT_ASSERT_PRE("item-count-ge-1", item_count >= 1,
		"Item count is 0");

	field_location = g_new0(struct bt_field_location, 1);
	if (!field_location) {
		BT_LIB_LOGE_APPEND_CAUSE("Failed to allocate one field location.");
		goto error;
	}

	bt_object_init_shared(&field_location->base, destroy_field_location);
	field_location->scope = scope;

	field_location->items = g_ptr_array_new_with_free_func(g_free);
	if (!field_location->items) {
		BT_LIB_LOGE_APPEND_CAUSE("Failed to allocate one GPtrArray.");
		goto error;
	}

	for (i = 0; i < item_count; ++i) {
		gchar *item = g_strdup(items[i]);

		g_ptr_array_add(field_location->items, item);
	}

	goto end;

error:
	BT_FIELD_LOCATION_PUT_REF_AND_RESET(field_location);

end:
	return field_location;
}

BT_EXPORT
bt_field_location_scope bt_field_location_get_root_scope(
		const bt_field_location *location)
{
	BT_ASSERT_PRE_FL_NON_NULL(location);

	return location->scope;
}

BT_EXPORT
uint64_t bt_field_location_get_item_count(
		const bt_field_location *location)
{
	BT_ASSERT_PRE_FL_NON_NULL(location);

	return location->items->len;
}

BT_EXPORT
const char *bt_field_location_get_item_by_index(
		const bt_field_location *location, uint64_t index)
{
	BT_ASSERT_PRE_FL_NON_NULL(location);
	BT_ASSERT_PRE_VALID_INDEX(index, location->items->len);

	return location->items->pdata[index];
}

BT_EXPORT
void bt_field_location_get_ref(const bt_field_location *field_location)
{
	bt_object_get_ref(field_location);
}

BT_EXPORT
void bt_field_location_put_ref(const bt_field_location *field_location)
{
	bt_object_put_ref(field_location);
}
