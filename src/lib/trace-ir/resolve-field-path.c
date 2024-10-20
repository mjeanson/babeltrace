/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2018 Philippe Proulx <pproulx@efficios.com>
 */

#define BT_LOG_TAG "LIB/RESOLVE-FIELD-PATH"
#include "lib/logging.h"

#include "lib/assert-cond.h"
#include "common/assert.h"
#include <babeltrace2/trace-ir/field-path.h>
#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

#include "field-class.h"
#include "field-path.h"
#include "resolve-field-path.h"
#include "common/common.h"

static
bool find_field_class_recursive(struct bt_field_class *fc,
		struct bt_field_class *tgt_fc, struct bt_field_path *field_path)
{
	bool found = false;

	if (tgt_fc == fc) {
		found = true;
		goto end;
	}

	if (bt_field_class_type_is(fc->type, BT_FIELD_CLASS_TYPE_OPTION)) {
		struct bt_field_class_option *opt_fc = (void *) fc;
		struct bt_field_path_item item = {
			.type = BT_FIELD_PATH_ITEM_TYPE_CURRENT_OPTION_CONTENT,
			.index = UINT64_C(-1),
		};

		bt_field_path_append_item(field_path, &item);
		found = find_field_class_recursive(opt_fc->content_fc,
			tgt_fc, field_path);
		if (found) {
			goto end;
		}

		bt_field_path_remove_last_item(field_path);
	} else if (fc->type == BT_FIELD_CLASS_TYPE_STRUCTURE ||
			bt_field_class_type_is(fc->type,
				BT_FIELD_CLASS_TYPE_VARIANT)) {
		struct bt_field_class_named_field_class_container *container_fc =
			(void *) fc;
		uint64_t i;

		for (i = 0; i < container_fc->named_fcs->len; i++) {
			struct bt_named_field_class *named_fc =
				container_fc->named_fcs->pdata[i];
			struct bt_field_path_item item = {
				.type = BT_FIELD_PATH_ITEM_TYPE_INDEX,
				.index = i,
			};

			bt_field_path_append_item(field_path, &item);
			found = find_field_class_recursive(named_fc->fc,
				tgt_fc, field_path);
			if (found) {
				goto end;
			}

			bt_field_path_remove_last_item(field_path);
		}
	} else if (bt_field_class_type_is(fc->type, BT_FIELD_CLASS_TYPE_ARRAY)) {
		struct bt_field_class_array *array_fc = (void *) fc;
		struct bt_field_path_item item = {
			.type = BT_FIELD_PATH_ITEM_TYPE_CURRENT_ARRAY_ELEMENT,
			.index = UINT64_C(-1),
		};

		bt_field_path_append_item(field_path, &item);
		found = find_field_class_recursive(array_fc->element_fc,
			tgt_fc, field_path);
		if (found) {
			goto end;
		}

		bt_field_path_remove_last_item(field_path);
	}

end:
	return found;
}

static
enum bt_resolve_field_xref_status find_field_class(
		struct bt_field_class *root_fc,
		enum bt_field_path_scope root_scope,
		struct bt_field_class *tgt_fc,
		struct bt_field_path **ret_field_path)
{
	enum bt_resolve_field_xref_status ret;
	struct bt_field_path *field_path = NULL;

	if (!root_fc) {
		ret = BT_RESOLVE_FIELD_XREF_STATUS_OK;
		goto end;
	}

	field_path = bt_field_path_create();
	if (!field_path) {
		ret = BT_RESOLVE_FIELD_XREF_STATUS_MEMORY_ERROR;
		goto end;
	}

	field_path->root = root_scope;
	if (!find_field_class_recursive(root_fc, tgt_fc, field_path)) {
		/* Not found here */
		BT_OBJECT_PUT_REF_AND_RESET(field_path);
	}

	ret = BT_RESOLVE_FIELD_XREF_STATUS_OK;

end:
	*ret_field_path = field_path;
	return ret;
}

static
enum bt_resolve_field_xref_status find_field_class_in_ctx(
		struct bt_field_class *fc,
		struct bt_resolve_field_xref_context *ctx,
		struct bt_field_path **ret_field_path)
{
	enum bt_resolve_field_xref_status ret;

	*ret_field_path = NULL;

	ret = find_field_class(ctx->packet_context,
		BT_FIELD_PATH_SCOPE_PACKET_CONTEXT, fc, ret_field_path);
	if (ret != BT_RESOLVE_FIELD_XREF_STATUS_OK || *ret_field_path) {
		goto end;
	}

	ret = find_field_class(ctx->event_common_context,
		BT_FIELD_PATH_SCOPE_EVENT_COMMON_CONTEXT, fc, ret_field_path);
	if (ret != BT_RESOLVE_FIELD_XREF_STATUS_OK || *ret_field_path) {
		goto end;
	}

	ret = find_field_class(ctx->event_specific_context,
		BT_FIELD_PATH_SCOPE_EVENT_SPECIFIC_CONTEXT, fc, ret_field_path);
	if (ret != BT_RESOLVE_FIELD_XREF_STATUS_OK || *ret_field_path) {
		goto end;
	}

	ret = find_field_class(ctx->event_payload,
		BT_FIELD_PATH_SCOPE_EVENT_PAYLOAD, fc, ret_field_path);
	if (ret != BT_RESOLVE_FIELD_XREF_STATUS_OK || *ret_field_path) {
		goto end;
	}

end:
	return ret;
}

BT_ASSERT_COND_DEV_FUNC
static inline
bool target_is_before_source(struct bt_field_path *src_field_path,
		struct bt_field_path *tgt_field_path)
{
	bool is_valid = true;
	uint64_t src_i = 0, tgt_i = 0;

	if (tgt_field_path->root < src_field_path->root) {
		goto end;
	}

	if (tgt_field_path->root > src_field_path->root) {
		is_valid = false;
		goto end;
	}

	BT_ASSERT(tgt_field_path->root == src_field_path->root);

	for (src_i = 0, tgt_i = 0; src_i < src_field_path->items->len &&
			tgt_i < tgt_field_path->items->len; src_i++, tgt_i++) {
		struct bt_field_path_item *src_fp_item =
			bt_field_path_borrow_item_by_index_inline(
				src_field_path, src_i);
		struct bt_field_path_item *tgt_fp_item =
			bt_field_path_borrow_item_by_index_inline(
				tgt_field_path, tgt_i);

		if (src_fp_item->type == BT_FIELD_PATH_ITEM_TYPE_INDEX &&
				tgt_fp_item->type == BT_FIELD_PATH_ITEM_TYPE_INDEX) {
			if (tgt_fp_item->index > src_fp_item->index) {
				is_valid = false;
				goto end;
			}
		}

		src_i++;
		tgt_i++;
	}

end:
	return is_valid;
}

BT_ASSERT_COND_DEV_FUNC
static inline
struct bt_field_class *borrow_root_field_class(
		struct bt_resolve_field_xref_context *ctx,
		enum bt_field_path_scope scope)
{
	switch (scope) {
	case BT_FIELD_PATH_SCOPE_PACKET_CONTEXT:
		return ctx->packet_context;
	case BT_FIELD_PATH_SCOPE_EVENT_COMMON_CONTEXT:
		return ctx->event_common_context;
	case BT_FIELD_PATH_SCOPE_EVENT_SPECIFIC_CONTEXT:
		return ctx->event_specific_context;
	case BT_FIELD_PATH_SCOPE_EVENT_PAYLOAD:
		return ctx->event_payload;
	default:
		bt_common_abort();
	}

	return NULL;
}

BT_ASSERT_COND_DEV_FUNC
static inline
struct bt_field_class *borrow_child_field_class(
		struct bt_field_class *parent_fc,
		struct bt_field_path_item *fp_item)
{
	struct bt_field_class *child_fc = NULL;

	if (bt_field_class_type_is(parent_fc->type,
			BT_FIELD_CLASS_TYPE_OPTION)) {
		struct bt_field_class_option *opt_fc = (void *) parent_fc;

		BT_ASSERT(fp_item->type ==
			BT_FIELD_PATH_ITEM_TYPE_CURRENT_OPTION_CONTENT);
		child_fc = opt_fc->content_fc;
	} else if (parent_fc->type == BT_FIELD_CLASS_TYPE_STRUCTURE ||
			bt_field_class_type_is(parent_fc->type,
				BT_FIELD_CLASS_TYPE_VARIANT)) {
		struct bt_field_class_named_field_class_container *container_fc =
			(void *) parent_fc;
		struct bt_named_field_class *named_fc;

		BT_ASSERT(fp_item->type == BT_FIELD_PATH_ITEM_TYPE_INDEX);
		named_fc = container_fc->named_fcs->pdata[fp_item->index];
		child_fc = named_fc->fc;
	} else if (bt_field_class_type_is(parent_fc->type,
			BT_FIELD_CLASS_TYPE_ARRAY)) {
		struct bt_field_class_array *array_fc = (void *) parent_fc;

		BT_ASSERT(fp_item->type ==
			BT_FIELD_PATH_ITEM_TYPE_CURRENT_ARRAY_ELEMENT);
		child_fc = array_fc->element_fc;
	}

	return child_fc;
}

BT_ASSERT_COND_DEV_FUNC
static inline
bool target_field_path_in_different_scope_has_struct_fc_only(
		struct bt_field_path *src_field_path,
		struct bt_field_path *tgt_field_path,
		struct bt_resolve_field_xref_context *ctx)
{
	bool is_valid = true;
	uint64_t i = 0;
	struct bt_field_class *fc;

	if (src_field_path->root == tgt_field_path->root) {
		goto end;
	}

	fc = borrow_root_field_class(ctx, tgt_field_path->root);

	for (i = 0; i < tgt_field_path->items->len; i++) {
		struct bt_field_path_item *fp_item =
			bt_field_path_borrow_item_by_index_inline(
				tgt_field_path, i);

		if (bt_field_class_type_is(fc->type,
				BT_FIELD_CLASS_TYPE_ARRAY) ||
				bt_field_class_type_is(fc->type,
					BT_FIELD_CLASS_TYPE_OPTION) ||
				bt_field_class_type_is(fc->type,
					BT_FIELD_CLASS_TYPE_VARIANT)) {
			is_valid = false;
			goto end;
		}

		BT_ASSERT(fp_item->type == BT_FIELD_PATH_ITEM_TYPE_INDEX);
		fc = borrow_child_field_class(fc, fp_item);
	}

end:
	return is_valid;
}

BT_ASSERT_COND_DEV_FUNC
static inline
bool lca_is_structure_field_class(struct bt_field_path *src_field_path,
		struct bt_field_path *tgt_field_path,
		struct bt_resolve_field_xref_context *ctx)
{
	bool is_valid = true;
	struct bt_field_class *src_fc;
	struct bt_field_class *tgt_fc;
	struct bt_field_class *prev_fc = NULL;
	uint64_t src_i = 0, tgt_i = 0;

	if (src_field_path->root != tgt_field_path->root) {
		goto end;
	}

	src_fc = borrow_root_field_class(ctx, src_field_path->root);
	tgt_fc = borrow_root_field_class(ctx, tgt_field_path->root);
	BT_ASSERT(src_fc);
	BT_ASSERT(tgt_fc);

	for (src_i = 0, tgt_i = 0; src_i < src_field_path->items->len &&
			tgt_i < tgt_field_path->items->len; src_i++, tgt_i++) {
		struct bt_field_path_item *src_fp_item =
			bt_field_path_borrow_item_by_index_inline(
				src_field_path, src_i);
		struct bt_field_path_item *tgt_fp_item =
			bt_field_path_borrow_item_by_index_inline(
				tgt_field_path, tgt_i);

		if (src_fc != tgt_fc) {
			if (!prev_fc) {
				/*
				 * This is correct: the LCA is the root
				 * scope field class, which must be a
				 * structure field class.
				 */
				break;
			}

			if (prev_fc->type != BT_FIELD_CLASS_TYPE_STRUCTURE) {
				is_valid = false;
			}

			break;
		}

		prev_fc = src_fc;
		src_fc = borrow_child_field_class(src_fc, src_fp_item);
		tgt_fc = borrow_child_field_class(tgt_fc, tgt_fp_item);
	}

end:
	return is_valid;
}

BT_ASSERT_COND_DEV_FUNC
static inline
bool lca_to_target_has_struct_fc_only(struct bt_field_path *src_field_path,
		struct bt_field_path *tgt_field_path,
		struct bt_resolve_field_xref_context *ctx)
{
	bool is_valid = true;
	struct bt_field_class *src_fc;
	struct bt_field_class *tgt_fc;
	uint64_t src_i = 0, tgt_i = 0;

	if (src_field_path->root != tgt_field_path->root) {
		goto end;
	}

	src_fc = borrow_root_field_class(ctx, src_field_path->root);
	tgt_fc = borrow_root_field_class(ctx, tgt_field_path->root);
	BT_ASSERT(src_fc);
	BT_ASSERT(tgt_fc);
	BT_ASSERT(src_fc == tgt_fc);

	/* Find LCA */
	for (src_i = 0, tgt_i = 0; src_i < src_field_path->items->len &&
			tgt_i < tgt_field_path->items->len; src_i++, tgt_i++) {
		struct bt_field_path_item *src_fp_item =
			bt_field_path_borrow_item_by_index_inline(
				src_field_path, src_i);
		struct bt_field_path_item *tgt_fp_item =
			bt_field_path_borrow_item_by_index_inline(
				tgt_field_path, tgt_i);

		if (src_i != tgt_i) {
			/* Next field class is different: LCA is `tgt_fc` */
			break;
		}

		src_fc = borrow_child_field_class(src_fc, src_fp_item);
		tgt_fc = borrow_child_field_class(tgt_fc, tgt_fp_item);
	}

	/* Only structure field classes to the target */
	for (; tgt_i < tgt_field_path->items->len; tgt_i++) {
		struct bt_field_path_item *tgt_fp_item =
			bt_field_path_borrow_item_by_index_inline(
				tgt_field_path, tgt_i);

		if (bt_field_class_type_is(tgt_fc->type,
				BT_FIELD_CLASS_TYPE_ARRAY) ||
				bt_field_class_type_is(tgt_fc->type,
					BT_FIELD_CLASS_TYPE_OPTION) ||
				bt_field_class_type_is(tgt_fc->type,
					BT_FIELD_CLASS_TYPE_VARIANT)) {
			is_valid = false;
			goto end;
		}

		tgt_fc = borrow_child_field_class(tgt_fc, tgt_fp_item);
	}

end:
	return is_valid;
}

BT_ASSERT_COND_DEV_FUNC
static inline
bool field_path_is_valid(struct bt_field_class *src_fc,
		struct bt_field_class *tgt_fc,
		struct bt_resolve_field_xref_context *ctx)
{
	struct bt_field_path *src_field_path;
	struct bt_field_path *tgt_field_path = NULL;
	enum bt_resolve_field_xref_status status;
	bool is_valid;

	status = find_field_class_in_ctx(src_fc, ctx, &src_field_path);
	BT_ASSERT(status == BT_RESOLVE_FIELD_XREF_STATUS_OK);

	if (!src_field_path) {
		BT_ASSERT_COND_DEV_MSG("Cannot find requesting field class in "
			"resolving context: %!+F", src_fc);
		is_valid = false;
		goto end;
	}

	status = find_field_class_in_ctx(tgt_fc, ctx, &tgt_field_path);
	BT_ASSERT(status == BT_RESOLVE_FIELD_XREF_STATUS_OK);

	if (!tgt_field_path) {
		BT_ASSERT_COND_DEV_MSG("Cannot find target field class in "
			"resolving context: %!+F", tgt_fc);
		is_valid = false;
		goto end;
	}

	/* Target must be before source */
	if (!target_is_before_source(src_field_path, tgt_field_path)) {
		BT_ASSERT_COND_DEV_MSG("Target field class is located after "
			"requesting field class: %![req-fc-]+F, %![tgt-fc-]+F",
			src_fc, tgt_fc);
		is_valid = false;
		goto end;
	}

	/*
	 * If target is in a different scope than source, there are no
	 * array or variant field classes on the way to the target.
	 */
	if (!target_field_path_in_different_scope_has_struct_fc_only(
			src_field_path, tgt_field_path, ctx)) {
		BT_ASSERT_COND_DEV_MSG("Target field class is located in a "
			"different scope than requesting field class, "
			"but within an array or a variant field class: "
			"%![req-fc-]+F, %![tgt-fc-]+F",
			src_fc, tgt_fc);
		is_valid = false;
		goto end;
	}

	/* Same scope: LCA must be a structure field class */
	if (!lca_is_structure_field_class(src_field_path, tgt_field_path, ctx)) {
		BT_ASSERT_COND_DEV_MSG("Lowest common ancestor of target and "
			"requesting field classes is not a structure field class: "
			"%![req-fc-]+F, %![tgt-fc-]+F",
			src_fc, tgt_fc);
		is_valid = false;
		goto end;
	}

	/* Same scope: path from LCA to target has no array/variant FTs */
	if (!lca_to_target_has_struct_fc_only(src_field_path, tgt_field_path,
			ctx)) {
		BT_ASSERT_COND_DEV_MSG("Path from lowest common ancestor of target "
			"and requesting field classes to target field class "
			"contains an array or a variant field class: "
			"%![req-fc-]+F, %![tgt-fc-]+F", src_fc, tgt_fc);
		is_valid = false;
		goto end;
	}

	is_valid = true;

end:
	bt_object_put_ref(src_field_path);
	bt_object_put_ref(tgt_field_path);
	return is_valid;
}

static
enum bt_resolve_field_xref_status resolve_field_path(
		struct bt_field_class *src_fc,
		struct bt_field_class *tgt_fc,
		struct bt_resolve_field_xref_context *ctx,
		const char *api_func,
		struct bt_field_path **ret_field_path)
{
	BT_ASSERT_PRE_DEV_FROM_FUNC(api_func, "valid-field-class",
		field_path_is_valid(src_fc, tgt_fc, ctx),
		"Invalid target field class: %![req-fc-]+F, %![tgt-fc-]+F",
		src_fc, tgt_fc);
	return find_field_class_in_ctx(tgt_fc, ctx, ret_field_path);
}

enum bt_resolve_field_xref_status bt_resolve_field_paths(
		struct bt_field_class *fc,
		struct bt_resolve_field_xref_context *ctx,
		const char *api_func)
{
	enum bt_resolve_field_xref_status status;

	BT_ASSERT(fc);

	/* Resolving part for dynamic array and variant field classes */
	if (bt_field_class_type_is(fc->type,
			BT_FIELD_CLASS_TYPE_OPTION_WITH_SELECTOR_FIELD)) {
		struct bt_field_class_option_with_selector_field *opt_fc = (void *) fc;

		if (opt_fc->selector_field_xref_kind == FIELD_XREF_KIND_PATH) {
			BT_ASSERT(opt_fc->selector_field.path.class);
			BT_ASSERT(!opt_fc->selector_field.path.path);
			status = resolve_field_path(
				fc, opt_fc->selector_field.path.class, ctx, __func__,
				&opt_fc->selector_field.path.path);
			if (status != BT_RESOLVE_FIELD_XREF_STATUS_OK) {
				goto end;
			}
		}
	} else if (fc->type == BT_FIELD_CLASS_TYPE_DYNAMIC_ARRAY_WITH_LENGTH_FIELD) {
		struct bt_field_class_array_dynamic *dyn_array_fc = (void *) fc;

		if (dyn_array_fc->length_field.xref_kind == FIELD_XREF_KIND_PATH) {
			BT_ASSERT(dyn_array_fc->length_field.path.class);
			BT_ASSERT(!dyn_array_fc->length_field.path.path);
			status = resolve_field_path(
				fc, dyn_array_fc->length_field.path.class, ctx, __func__,
				&dyn_array_fc->length_field.path.path);
			if (status != BT_RESOLVE_FIELD_XREF_STATUS_OK) {
				goto end;
			}
		}
	} else if (bt_field_class_type_is(fc->type,
			BT_FIELD_CLASS_TYPE_VARIANT_WITH_SELECTOR_FIELD)) {
		struct bt_field_class_variant_with_selector_field *var_fc =
			(void *) fc;

		if (var_fc->selector_field_xref_kind == FIELD_XREF_KIND_PATH) {
			BT_ASSERT(var_fc->selector_field.path.class);
			BT_ASSERT(!var_fc->selector_field.path.path);
			status = resolve_field_path(fc,
				(void *) var_fc->selector_field.path.class, ctx,
				__func__, &var_fc->selector_field.path.path);
			if (status != BT_RESOLVE_FIELD_XREF_STATUS_OK) {
				goto end;
			}
		}
	}

	/* Recursive part */
	if (bt_field_class_type_is(fc->type, BT_FIELD_CLASS_TYPE_OPTION)) {
		struct bt_field_class_option *opt_fc = (void *) fc;

		status = bt_resolve_field_paths(opt_fc->content_fc, ctx, api_func);
		if (status != BT_RESOLVE_FIELD_XREF_STATUS_OK) {
			goto end;
		}
	} else if (fc->type == BT_FIELD_CLASS_TYPE_STRUCTURE ||
			bt_field_class_type_is(fc->type,
				BT_FIELD_CLASS_TYPE_VARIANT)) {
		struct bt_field_class_named_field_class_container *container_fc =
			(void *) fc;
		uint64_t i;

		for (i = 0; i < container_fc->named_fcs->len; i++) {
			struct bt_named_field_class *named_fc =
				container_fc->named_fcs->pdata[i];

			status = bt_resolve_field_paths(named_fc->fc, ctx,
				api_func);
			if (status != BT_RESOLVE_FIELD_XREF_STATUS_OK) {
				goto end;
			}
		}
	} else if (bt_field_class_type_is(fc->type,
			BT_FIELD_CLASS_TYPE_ARRAY)) {
		struct bt_field_class_array *array_fc = (void *) fc;

		status = bt_resolve_field_paths(array_fc->element_fc, ctx,
			api_func);
		if (status != BT_RESOLVE_FIELD_XREF_STATUS_OK) {
			goto end;
		}
	}

	status = BT_RESOLVE_FIELD_XREF_STATUS_OK;

end:
	return status;
}
