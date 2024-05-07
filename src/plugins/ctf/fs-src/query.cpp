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

#include "cpp-common/bt2/exc.hpp"
#include "cpp-common/bt2c/file-utils.hpp"
#include "cpp-common/bt2c/glib-up.hpp"

#include "plugins/common/param-validation/param-validation.h"

#include "../common/src/metadata/metadata-stream-parser-utils.hpp"
#include "../common/src/metadata/tsdl/metadata-stream-decoder.hpp"
#include "data-stream-file.hpp"
#include "fs.hpp"
#include "metadata.hpp"
#include "query.hpp"

#define METADATA_TEXT_SIG "/* CTF 1.8"

struct range
{
    int64_t begin_ns = 0;
    int64_t end_ns = 0;
    bool set = false;
};

static bt_param_validation_map_value_entry_descr metadataInfoQueryParamsDesc[] = {
    {"path", BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_MANDATORY,
     bt_param_validation_value_descr::makeString()},
    BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_END};

bt2::Value::Shared metadata_info_query(const bt2::ConstMapValue params, const bt2c::Logger& logger)
{
    gchar *validateError = nullptr;
    const auto validationStatus = bt_param_validation_validate(
        params.libObjPtr(), metadataInfoQueryParamsDesc, &validateError);

    if (validationStatus == BT_PARAM_VALIDATION_STATUS_MEMORY_ERROR) {
        throw bt2::MemoryError {};
    } else if (validationStatus == BT_PARAM_VALIDATION_STATUS_VALIDATION_ERROR) {
        const bt2c::GCharUP deleter {validateError};

        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(logger, bt2::Error, "{}", validateError);
    }

    const auto path = params["path"]->asString().value();

    try {
        const auto buffer = bt2c::dataFromFile(fmt::format("{}/metadata", path), logger, true);
        ctf::src::MetadataStreamDecoder decoder {logger};
        auto plainText = decoder.decode(buffer);
        const auto result = bt2::MapValue::create();

        /*
         * If the metadata does not already start with the plaintext metadata
         * signature, prepend it.
         */
        if (plainText.rfind(METADATA_TEXT_SIG, 0) != 0) {
            plainText.insert(0, std::string {METADATA_TEXT_SIG} + " */\n\n");
        }

        result->insert("text", plainText.data());
        result->insert("is-packetized", decoder.pktInfo().has_value());
        return result;
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW_SPEC(logger, "Error reading metadata file");
    }
}

static void add_range(const bt2::MapValue info, const range& range, const char *range_name)
{
    if (!range.set) {
        /* Not an error. */
        return;
    }

    const auto rangeMap = info.insertEmptyMap(range_name);
    rangeMap.insert("begin", range.begin_ns);
    rangeMap.insert("end", range.end_ns);
}

static void populate_stream_info(struct ctf_fs_ds_file_group *group, const bt2::MapValue groupInfo)
{
    /*
     * Since each `struct ctf_fs_ds_file_group` has a sorted array of
     * `struct ctf_fs_ds_index_entry`, we can compute the stream range from
     * the timestamp_begin of the first index entry and the timestamp_end
     * of the last index entry.
     */
    BT_ASSERT(!group->index.entries.empty());

    /* First entry. */
    const auto& first_ds_index_entry = group->index.entries.front();

    /* Last entry. */
    const auto& last_ds_index_entry = group->index.entries.back();

    range stream_range;
    stream_range.begin_ns = first_ds_index_entry.timestamp_begin_ns;
    stream_range.end_ns = last_ds_index_entry.timestamp_end_ns;

    /*
     * If any of the begin and end timestamps is not set it means that
     * packets don't include `timestamp_begin` _and_ `timestamp_end` fields
     * in their packet context so we can't set the range.
     */
    stream_range.set = stream_range.begin_ns != UINT64_C(-1) && stream_range.end_ns != UINT64_C(-1);

    add_range(groupInfo, stream_range, "range-ns");
    groupInfo.insert("port-name", ctf_fs_make_port_name(group));
}

static void populate_trace_info(const struct ctf_fs_trace *trace, const bt2::MapValue traceInfo,
                                const bt2c::Logger& logger)
{
    /* Add trace range info only if it contains streams. */
    if (trace->ds_file_groups.empty()) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(logger, bt2::Error,
                                               "Trace has no streams: trace-path={}", trace->path);
    }

    const auto fileGroups = traceInfo.insertEmptyArray("stream-infos");

    /* Find range of all stream groups, and of the trace. */
    for (const auto& group : trace->ds_file_groups) {
        const auto groupInfo = fileGroups.appendEmptyMap();
        populate_stream_info(group.get(), groupInfo);
    }
}

bt2::Value::Shared trace_infos_query(const bt2::ConstMapValue params, const bt2c::Logger& logger)
{
    const auto parameters = read_src_fs_parameters(params, logger);
    ctf_fs_component ctf_fs {parameters.clkClsCfg, logger};

    if (ctf_fs_component_create_ctf_fs_trace(
            &ctf_fs, parameters.inputs,
            parameters.traceName ? parameters.traceName->c_str() : nullptr, nullptr)) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(logger, bt2::Error, "Failed to create trace");
    }

    const auto result = bt2::ArrayValue::create();
    const auto traceInfo = result->appendEmptyMap();
    populate_trace_info(ctf_fs.trace.get(), traceInfo, logger);

    return result;
}

static bt_param_validation_map_value_entry_descr supportInfoQueryParamsDesc[] = {
    {"type", BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_MANDATORY,
     bt_param_validation_value_descr::makeString()},
    {"input", BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_MANDATORY,
     bt_param_validation_value_descr::makeString()},
    BT_PARAM_VALIDATION_MAP_VALUE_ENTRY_END};

bt2::Value::Shared support_info_query(const bt2::ConstMapValue params, const bt2c::Logger& logger)
{
    gchar *validateError = NULL;
    const auto validationStatus = bt_param_validation_validate(
        params.libObjPtr(), supportInfoQueryParamsDesc, &validateError);

    if (validationStatus == BT_PARAM_VALIDATION_STATUS_MEMORY_ERROR) {
        throw bt2::MemoryError {};
    } else if (validationStatus == BT_PARAM_VALIDATION_STATUS_VALIDATION_ERROR) {
        const bt2c::GCharUP deleter {validateError};

        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(logger, bt2::Error, "{}", validateError);
    }

    const auto type = params["type"]->asString().value();

    if (strcmp(type, "directory") != 0) {
        /*
         * The input type is not a directory so we are 100% sure it's not a CTF
         * 1.8 trace as it would need a directory with at least 1 metadata file
         * and 1 data stream file.
         */
        const auto result = bt2::MapValue::create();
        result->insert("weight", 0.0f);
        return result;
    }

    const auto input = params["input"]->asString().value();

    const auto result = bt2::MapValue::create();
    try {
        const auto buffer = bt2c::dataFromFile(fmt::format("{}/metadata", input), logger, false);
        const auto parseRet = ctf::src::parseMetadataStream({}, {}, buffer, logger);

        BT_ASSERT(parseRet.traceCls);

        /*
         * We were able to parse the metadata file, so we are confident it's a
         * CTF trace.
         */
        /* ⚠️ TODO: also consider namespace and name */
        result->insert("weight", 0.75);
        if (parseRet.traceCls->uid()) {
            result->insert("group", *parseRet.traceCls->uid());
        }
    } catch (const bt2c::NoSuchFileOrDirectoryError&) {
        /*
         * Failing to find the metadata file is not an error, it simply
         * indicates that the directory is not a trace. Report appropriate
         * weight of zero.
         */
        result->insert("weight", 0.0);
    }

    return result;
}
