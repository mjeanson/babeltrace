/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Babeltrace CTF file system Reader Component queries
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <sys/types.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/libc-up.hpp"

#include "../common/src/metadata/tsdl/decoder.hpp"
#include "fs.hpp"
#include "query.hpp"

#define METADATA_TEXT_SIG "/* CTF 1.8"

struct range
{
    int64_t begin_ns = 0;
    int64_t end_ns = 0;
    bool set = false;
};

bt_component_class_query_method_status metadata_info_query(const bt_value *params,
                                                           const bt2c::Logger& logger,
                                                           const bt_value **user_result)
{
    bt_component_class_query_method_status status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
    bt_value *result = NULL;
    const bt_value *path_value = NULL;
    bt2c::FileUP metadata_fp;
    int ret;
    int bo;
    const char *path;
    bool is_packetized;
    ctf_metadata_decoder_up decoder;
    ctf_metadata_decoder_config decoder_cfg {logger};
    enum ctf_metadata_decoder_status decoder_status;
    GString *g_metadata_text = NULL;
    const char *plaintext;

    result = bt_value_map_create();
    if (!result) {
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_MEMORY_ERROR;
        goto error;
    }

    BT_ASSERT(params);

    if (!bt_value_is_map(params)) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Query parameters is not a map value object.");
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
        goto error;
    }

    path_value = bt_value_map_borrow_entry_value_const(params, "path");
    if (!path_value) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Mandatory `path` parameter missing");
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
        goto error;
    }

    if (!bt_value_is_string(path_value)) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "`path` parameter is required to be a string value");
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
        goto error;
    }

    path = bt_value_string_get(path_value);

    BT_ASSERT(path);
    metadata_fp.reset(ctf_fs_metadata_open_file(path, logger));
    if (!metadata_fp) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot open trace metadata: path=\"{}\".", path);
        goto error;
    }

    ret = ctf_metadata_decoder_is_packetized(metadata_fp.get(), &is_packetized, &bo, logger);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            logger, "Cannot check whether or not the metadata stream is packetized: path=\"{}\".",
            path);
        goto error;
    }

    decoder_cfg.keep_plain_text = true;
    decoder = ctf_metadata_decoder_create(&decoder_cfg);
    if (!decoder) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot create metadata decoder: path=\"{}\".", path);
        goto error;
    }

    rewind(metadata_fp.get());
    decoder_status = ctf_metadata_decoder_append_content(decoder.get(), metadata_fp.get());
    if (decoder_status) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            logger, "Cannot update metadata decoder's content: path=\"{}\".", path);
        goto error;
    }

    plaintext = ctf_metadata_decoder_get_text(decoder.get());
    g_metadata_text = g_string_new(NULL);

    if (!g_metadata_text) {
        goto error;
    }

    if (strncmp(plaintext, METADATA_TEXT_SIG, sizeof(METADATA_TEXT_SIG) - 1) != 0) {
        g_string_assign(g_metadata_text, METADATA_TEXT_SIG);
        g_string_append(g_metadata_text, " */\n\n");
    }

    g_string_append(g_metadata_text, plaintext);
    ret = bt_value_map_insert_string_entry(result, "text", g_metadata_text->str);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot insert metadata text into query result.");
        goto error;
    }

    ret = bt_value_map_insert_bool_entry(result, "is-packetized", is_packetized);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(
            logger, "Cannot insert \"is-packetized\" attribute into query result.");
        goto error;
    }

    goto end;

error:
    BT_VALUE_PUT_REF_AND_RESET(result);
    result = NULL;

    if (status >= 0) {
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
    }

end:
    if (g_metadata_text) {
        g_string_free(g_metadata_text, TRUE);
    }

    *user_result = result;
    return status;
}

static int add_range(bt_value *info, struct range *range, const char *range_name)
{
    int ret = 0;
    bt_value_map_insert_entry_status status;
    bt_value *range_map;

    if (!range->set) {
        /* Not an error. */
        goto end;
    }

    status = bt_value_map_insert_empty_map_entry(info, range_name, &range_map);
    if (status != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
        ret = -1;
        goto end;
    }

    status = bt_value_map_insert_signed_integer_entry(range_map, "begin", range->begin_ns);
    if (status != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
        ret = -1;
        goto end;
    }

    status = bt_value_map_insert_signed_integer_entry(range_map, "end", range->end_ns);
    if (status != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
        ret = -1;
        goto end;
    }

end:
    return ret;
}

static int populate_stream_info(struct ctf_fs_ds_file_group *group, bt_value *group_info,
                                struct range *stream_range)
{
    int ret = 0;
    bt_value_map_insert_entry_status insert_status;
    struct ctf_fs_ds_index_entry *first_ds_index_entry, *last_ds_index_entry;
    bt2c::GCharUP port_name;

    /*
     * Since each `struct ctf_fs_ds_file_group` has a sorted array of
     * `struct ctf_fs_ds_index_entry`, we can compute the stream range from
     * the timestamp_begin of the first index entry and the timestamp_end
     * of the last index entry.
     */
    BT_ASSERT(group->index);
    BT_ASSERT(group->index->entries);
    BT_ASSERT(group->index->entries->len > 0);

    /* First entry. */
    first_ds_index_entry =
        (struct ctf_fs_ds_index_entry *) g_ptr_array_index(group->index->entries, 0);

    /* Last entry. */
    last_ds_index_entry = (struct ctf_fs_ds_index_entry *) g_ptr_array_index(
        group->index->entries, group->index->entries->len - 1);

    stream_range->begin_ns = first_ds_index_entry->timestamp_begin_ns;
    stream_range->end_ns = last_ds_index_entry->timestamp_end_ns;

    /*
     * If any of the begin and end timestamps is not set it means that
     * packets don't include `timestamp_begin` _and_ `timestamp_end` fields
     * in their packet context so we can't set the range.
     */
    stream_range->set =
        stream_range->begin_ns != UINT64_C(-1) && stream_range->end_ns != UINT64_C(-1);

    ret = add_range(group_info, stream_range, "range-ns");
    if (ret) {
        goto end;
    }

    port_name = ctf_fs_make_port_name(group);
    if (!port_name) {
        ret = -1;
        goto end;
    }

    insert_status = bt_value_map_insert_string_entry(group_info, "port-name", port_name.get());
    if (insert_status != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
        ret = -1;
        goto end;
    }

end:
    return ret;
}

static int populate_trace_info(const struct ctf_fs_trace *trace, bt_value *trace_info,
                               const bt2c::Logger& logger)
{
    int ret = 0;
    size_t group_idx;
    bt_value_map_insert_entry_status insert_status;
    bt_value_array_append_element_status append_status;
    bt_value *file_groups = NULL;

    BT_ASSERT(trace->ds_file_groups);
    /* Add trace range info only if it contains streams. */
    if (trace->ds_file_groups->len == 0) {
        ret = -1;
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Trace has no streams: trace-path={}",
                                     trace->path->str);
        goto end;
    }

    insert_status = bt_value_map_insert_empty_array_entry(trace_info, "stream-infos", &file_groups);
    if (insert_status != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
        ret = -1;
        goto end;
    }

    /* Find range of all stream groups, and of the trace. */
    for (group_idx = 0; group_idx < trace->ds_file_groups->len; group_idx++) {
        bt_value *group_info;
        range group_range;
        ctf_fs_ds_file_group *group =
            (ctf_fs_ds_file_group *) g_ptr_array_index(trace->ds_file_groups, group_idx);

        append_status = bt_value_array_append_empty_map_element(file_groups, &group_info);
        if (append_status != BT_VALUE_ARRAY_APPEND_ELEMENT_STATUS_OK) {
            ret = -1;
            goto end;
        }

        ret = populate_stream_info(group, group_info, &group_range);
        if (ret) {
            goto end;
        }
    }

end:
    return ret;
}

bt_component_class_query_method_status
trace_infos_query(const bt_value *params, const bt2c::Logger& logger, const bt_value **user_result)
{
    ctf_fs_component::UP ctf_fs;
    bt_component_class_query_method_status status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;
    bt_value *result = NULL;
    const bt_value *inputs_value = NULL;
    const bt_value *trace_name_value;
    int ret = 0;
    bt_value *trace_info = NULL;
    bt_value_array_append_element_status append_status;

    BT_ASSERT(params);

    if (!bt_value_is_map(params)) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Query parameters is not a map value object.");
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
        goto error;
    }

    ctf_fs = ctf_fs_component_create(logger);
    if (!ctf_fs) {
        goto error;
    }

    if (!read_src_fs_parameters(params, &inputs_value, &trace_name_value, ctf_fs.get())) {
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
        goto error;
    }

    if (ctf_fs_component_create_ctf_fs_trace(ctf_fs.get(), inputs_value, trace_name_value, NULL)) {
        goto error;
    }

    result = bt_value_array_create();
    if (!result) {
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_MEMORY_ERROR;
        goto error;
    }

    append_status = bt_value_array_append_empty_map_element(result, &trace_info);
    if (append_status != BT_VALUE_ARRAY_APPEND_ELEMENT_STATUS_OK) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Failed to create trace info map.");
        goto error;
    }

    ret = populate_trace_info(ctf_fs->trace, trace_info, logger);
    if (ret) {
        goto error;
    }

    goto end;

error:
    BT_VALUE_PUT_REF_AND_RESET(result);

    if (status >= 0) {
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
    }

end:
    *user_result = result;
    return status;
}

bt_component_class_query_method_status
support_info_query(const bt_value *params, const bt2c::Logger& logger, const bt_value **user_result)
{
    const bt_value *input_type_value;
    const char *input_type;
    bt_component_class_query_method_status status;
    bt_value_map_insert_entry_status insert_entry_status;
    double weight = 0;
    bt2c::GCharUP metadata_path;
    bt_value *result = NULL;
    ctf_metadata_decoder_up metadata_decoder;
    FILE *metadata_file = NULL;
    char uuid_str[BT_UUID_STR_LEN + 1];
    bool has_uuid = false;
    const bt_value *input_value;
    const char *input;

    input_type_value = bt_value_map_borrow_entry_value_const(params, "type");
    BT_ASSERT(input_type_value);
    BT_ASSERT(bt_value_get_type(input_type_value) == BT_VALUE_TYPE_STRING);
    input_type = bt_value_string_get(input_type_value);

    if (strcmp(input_type, "directory") != 0) {
        goto create_result;
    }

    input_value = bt_value_map_borrow_entry_value_const(params, "input");
    BT_ASSERT(input_value);
    BT_ASSERT(bt_value_get_type(input_value) == BT_VALUE_TYPE_STRING);
    input = bt_value_string_get(input_value);

    metadata_path.reset(g_build_filename(input, CTF_FS_METADATA_FILENAME, NULL));
    if (!metadata_path) {
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_MEMORY_ERROR;
        goto end;
    }

    metadata_file = g_fopen(metadata_path.get(), "rb");
    if (metadata_file) {
        enum ctf_metadata_decoder_status decoder_status;
        bt_uuid_t uuid;

        ctf_metadata_decoder_config metadata_decoder_config {logger};

        metadata_decoder = ctf_metadata_decoder_create(&metadata_decoder_config);
        if (!metadata_decoder) {
            status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
            goto end;
        }

        decoder_status = ctf_metadata_decoder_append_content(metadata_decoder.get(), metadata_file);
        if (decoder_status != CTF_METADATA_DECODER_STATUS_OK) {
            BT_CPPLOGW_SPEC(logger, "cannot append metadata content: metadata-decoder-status={}",
                            decoder_status);
            status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_ERROR;
            goto end;
        }

        /*
         * We were able to parse the metadata file, so we are
         * confident it's a CTF trace.
         */
        weight = 0.75;

        /* If the trace has a UUID, return the stringified UUID as the group. */
        if (ctf_metadata_decoder_get_trace_class_uuid(metadata_decoder.get(), uuid) == 0) {
            bt_uuid_to_str(uuid, uuid_str);
            has_uuid = true;
        }
    }

create_result:
    result = bt_value_map_create();
    if (!result) {
        status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_MEMORY_ERROR;
        goto end;
    }

    insert_entry_status = bt_value_map_insert_real_entry(result, "weight", weight);
    if (insert_entry_status != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
        status = (bt_component_class_query_method_status) insert_entry_status;
        goto end;
    }

    /* We are not supposed to have weight == 0 and a UUID. */
    BT_ASSERT(weight > 0 || !has_uuid);

    if (weight > 0 && has_uuid) {
        insert_entry_status = bt_value_map_insert_string_entry(result, "group", uuid_str);
        if (insert_entry_status != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK) {
            status = (bt_component_class_query_method_status) insert_entry_status;
            goto end;
        }
    }

    *user_result = result;
    result = NULL;
    status = BT_COMPONENT_CLASS_QUERY_METHOD_STATUS_OK;

end:
    bt_value_put_ref(result);

    return status;
}
