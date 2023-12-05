/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2017 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#include <glib.h>
#include <stdint.h>
#include <stdio.h>

#include "compat/endian.h" /* IWYU pragma: keep  */
#include "compat/mman.h"   /* IWYU: pragma keep  */
#include "cpp-common/bt2s/make-unique.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "../common/src/msg-iter/msg-iter.hpp"
#include "data-stream-file.hpp"
#include "file.hpp"
#include "fs.hpp"
#include "lttng-index.hpp"

static inline size_t remaining_mmap_bytes(struct ctf_fs_ds_file *ds_file)
{
    BT_ASSERT_DBG(ds_file->mmap_len >= ds_file->request_offset_in_mapping);
    return ds_file->mmap_len - ds_file->request_offset_in_mapping;
}

/*
 * Return true if `offset_in_file` is in the current mapping.
 */

static bool offset_ist_mapped(struct ctf_fs_ds_file *ds_file, off_t offset_in_file)
{
    return offset_in_file >= ds_file->mmap_offset_in_file &&
           offset_in_file < (ds_file->mmap_offset_in_file + ds_file->mmap_len);
}

static enum ctf_msg_iter_medium_status ds_file_munmap(struct ctf_fs_ds_file *ds_file)
{
    enum ctf_msg_iter_medium_status status;

    BT_ASSERT(ds_file);

    if (!ds_file->mmap_addr) {
        status = CTF_MSG_ITER_MEDIUM_STATUS_OK;
        goto end;
    }

    if (bt_munmap(ds_file->mmap_addr, ds_file->mmap_len)) {
        BT_CPPLOGE_ERRNO_SPEC(ds_file->logger, "Cannot memory-unmap file",
                              ": address={}, size={}, file_path=\"{}\", file={}",
                              fmt::ptr(ds_file->mmap_addr), ds_file->mmap_len,
                              ds_file->file ? ds_file->file->path : "NULL",
                              ds_file->file ? fmt::ptr(ds_file->file->fp) : NULL);
        status = CTF_MSG_ITER_MEDIUM_STATUS_ERROR;
        goto end;
    }

    ds_file->mmap_addr = NULL;

    status = CTF_MSG_ITER_MEDIUM_STATUS_OK;
end:
    return status;
}

/*
 * mmap a region of `ds_file` such that `requested_offset_in_file` is in the
 * mapping.  If the currently mmap-ed region already contains
 * `requested_offset_in_file`, the mapping is kept.
 *
 * Set `ds_file->requested_offset_in_mapping` based on `request_offset_in_file`,
 * such that the next call to `request_bytes` will return bytes starting at that
 * position.
 *
 * `requested_offset_in_file` must be a valid offset in the file.
 */
static enum ctf_msg_iter_medium_status ds_file_mmap(struct ctf_fs_ds_file *ds_file,
                                                    off_t requested_offset_in_file)
{
    enum ctf_msg_iter_medium_status status;

    /* Ensure the requested offset is in the file range. */
    BT_ASSERT(requested_offset_in_file >= 0);
    BT_ASSERT(requested_offset_in_file < ds_file->file->size);

    /*
     * If the mapping already contains the requested offset, just adjust
     * requested_offset_in_mapping.
     */
    if (offset_ist_mapped(ds_file, requested_offset_in_file)) {
        ds_file->request_offset_in_mapping =
            requested_offset_in_file - ds_file->mmap_offset_in_file;
        status = CTF_MSG_ITER_MEDIUM_STATUS_OK;
        goto end;
    }

    /* Unmap old region */
    status = ds_file_munmap(ds_file);
    if (status != CTF_MSG_ITER_MEDIUM_STATUS_OK) {
        goto end;
    }

    /*
     * Compute a mapping that has the required alignment properties and
     * contains `requested_offset_in_file`.
     */
    ds_file->request_offset_in_mapping =
        requested_offset_in_file %
        bt_mmap_get_offset_align_size(static_cast<int>(ds_file->logger.level()));
    ds_file->mmap_offset_in_file = requested_offset_in_file - ds_file->request_offset_in_mapping;
    ds_file->mmap_len =
        MIN(ds_file->file->size - ds_file->mmap_offset_in_file, ds_file->mmap_max_len);

    BT_ASSERT(ds_file->mmap_len > 0);

    ds_file->mmap_addr =
        bt_mmap(ds_file->mmap_len, PROT_READ, MAP_PRIVATE, fileno(ds_file->file->fp.get()),
                ds_file->mmap_offset_in_file, static_cast<int>(ds_file->logger.level()));
    if (ds_file->mmap_addr == MAP_FAILED) {
        BT_CPPLOGE_SPEC(ds_file->logger,
                        "Cannot memory-map address (size {}) of file \"{}\" ({}) at offset {}: {}",
                        ds_file->mmap_len, ds_file->file->path, fmt::ptr(ds_file->file->fp),
                        (intmax_t) ds_file->mmap_offset_in_file, strerror(errno));
        status = CTF_MSG_ITER_MEDIUM_STATUS_ERROR;
        goto end;
    }

    status = CTF_MSG_ITER_MEDIUM_STATUS_OK;

end:
    return status;
}

/*
 * Change the mapping of the file to read the region that follows the current
 * mapping.
 *
 * If the file hasn't been mapped yet, then everything (mmap_offset_in_file,
 * mmap_len, request_offset_in_mapping) should have the value 0, which will
 * result in the beginning of the file getting mapped.
 *
 * return _EOF if the current mapping is the end of the file.
 */

static enum ctf_msg_iter_medium_status ds_file_mmap_next(struct ctf_fs_ds_file *ds_file)
{
    enum ctf_msg_iter_medium_status status;

    /*
     * If we're called, it's because more bytes are requested but we have
     * given all the bytes of the current mapping.
     */
    BT_ASSERT(ds_file->request_offset_in_mapping == ds_file->mmap_len);

    /*
     * If the current mapping coincides with the end of the file, there is
     * no next mapping.
     */
    if (ds_file->mmap_offset_in_file + ds_file->mmap_len == ds_file->file->size) {
        status = CTF_MSG_ITER_MEDIUM_STATUS_EOF;
        goto end;
    }

    status = ds_file_mmap(ds_file, ds_file->mmap_offset_in_file + ds_file->mmap_len);

end:
    return status;
}

static enum ctf_msg_iter_medium_status medop_request_bytes(size_t request_sz, uint8_t **buffer_addr,
                                                           size_t *buffer_sz, void *data)
{
    enum ctf_msg_iter_medium_status status = CTF_MSG_ITER_MEDIUM_STATUS_OK;
    struct ctf_fs_ds_file *ds_file = (struct ctf_fs_ds_file *) data;

    BT_ASSERT(request_sz > 0);

    /*
     * Check if we have at least one memory-mapped byte left. If we don't,
     * mmap the next file.
     */
    if (remaining_mmap_bytes(ds_file) == 0) {
        /* Are we at the end of the file? */
        if (ds_file->mmap_offset_in_file >= ds_file->file->size) {
            BT_CPPLOGD_SPEC(ds_file->logger, "Reached end of file \"{}\" ({})", ds_file->file->path,
                            fmt::ptr(ds_file->file->fp));
            status = CTF_MSG_ITER_MEDIUM_STATUS_EOF;
            goto end;
        }

        status = ds_file_mmap_next(ds_file);
        switch (status) {
        case CTF_MSG_ITER_MEDIUM_STATUS_OK:
            break;
        case CTF_MSG_ITER_MEDIUM_STATUS_EOF:
            goto end;
        default:
            BT_CPPLOGE_SPEC(ds_file->logger, "Cannot memory-map next region of file \"{}\" ({})",
                            ds_file->file->path, fmt::ptr(ds_file->file->fp));
            goto error;
        }
    }

    BT_ASSERT(remaining_mmap_bytes(ds_file) > 0);
    *buffer_sz = MIN(remaining_mmap_bytes(ds_file), request_sz);

    BT_ASSERT(ds_file->mmap_addr);
    *buffer_addr = ((uint8_t *) ds_file->mmap_addr) + ds_file->request_offset_in_mapping;

    ds_file->request_offset_in_mapping += *buffer_sz;
    goto end;

error:
    status = CTF_MSG_ITER_MEDIUM_STATUS_ERROR;

end:
    return status;
}

static bt_stream *medop_borrow_stream(bt_stream_class *stream_class, int64_t, void *data)
{
    struct ctf_fs_ds_file *ds_file = (struct ctf_fs_ds_file *) data;
    bt_stream_class *ds_file_stream_class;
    bt_stream *stream = NULL;

    ds_file_stream_class = ds_file->stream->cls().libObjPtr();

    if (stream_class != ds_file_stream_class) {
        /*
         * Not supported: two packets described by two different
         * stream classes within the same data stream file.
         */
        goto end;
    }

    stream = ds_file->stream->libObjPtr();

end:
    return stream;
}

static enum ctf_msg_iter_medium_status medop_seek(off_t offset, void *data)
{
    struct ctf_fs_ds_file *ds_file = (struct ctf_fs_ds_file *) data;

    BT_ASSERT(offset >= 0);
    BT_ASSERT(offset < ds_file->file->size);

    return ds_file_mmap(ds_file, offset);
}

struct ctf_msg_iter_medium_ops ctf_fs_ds_file_medops = {
    medop_request_bytes,
    medop_seek,
    nullptr,
    medop_borrow_stream,
};

struct ctf_fs_ds_group_medops_data
{
    explicit ctf_fs_ds_group_medops_data(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/DS-GROUP-MEDOPS"}
    {
    }

    bt2c::Logger logger;

    /* Weak, set once at creation time. */
    struct ctf_fs_ds_file_group *ds_file_group = nullptr;

    /*
     * Index (as in element rank) of the index entry of ds_file_groups'
     * index we will read next (so, the one after the one we are reading
     * right now).
     */
    guint next_index_entry_index = 0;

    /*
     * File we are currently reading.  Changes whenever we switch to
     * reading another data file.
     */
    ctf_fs_ds_file::UP file;

    /* Weak, for context / logging / appending causes. */
    bt_self_message_iterator *self_msg_iter = nullptr;
};

static enum ctf_msg_iter_medium_status medop_group_request_bytes(size_t request_sz,
                                                                 uint8_t **buffer_addr,
                                                                 size_t *buffer_sz, void *void_data)
{
    struct ctf_fs_ds_group_medops_data *data = (struct ctf_fs_ds_group_medops_data *) void_data;

    /* Return bytes from the current file. */
    return medop_request_bytes(request_sz, buffer_addr, buffer_sz, data->file.get());
}

static bt_stream *medop_group_borrow_stream(bt_stream_class *stream_class, int64_t stream_id,
                                            void *void_data)
{
    struct ctf_fs_ds_group_medops_data *data = (struct ctf_fs_ds_group_medops_data *) void_data;

    return medop_borrow_stream(stream_class, stream_id, data->file.get());
}

/*
 * Set `data->file` to prepare it to read the packet described
 * by `index_entry`.
 */

static enum ctf_msg_iter_medium_status
ctf_fs_ds_group_medops_set_file(struct ctf_fs_ds_group_medops_data *data,
                                struct ctf_fs_ds_index_entry *index_entry)
{
    enum ctf_msg_iter_medium_status status;

    BT_ASSERT(data);
    BT_ASSERT(index_entry);

    /* Check if that file is already the one mapped. */
    if (!data->file || data->file->file->path != index_entry->path) {
        /* Create the new file. */
        data->file =
            ctf_fs_ds_file_create(data->ds_file_group->ctf_fs_trace, data->ds_file_group->stream,
                                  index_entry->path, data->logger);
        if (!data->file) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(data->logger, "failed to create ctf_fs_ds_file.");
            status = CTF_MSG_ITER_MEDIUM_STATUS_ERROR;
            goto end;
        }
    }

    /*
     * Ensure the right portion of the file will be returned on the next
     * request_bytes call.
     */
    status = ds_file_mmap(data->file.get(), index_entry->offset.bytes());
    if (status != CTF_MSG_ITER_MEDIUM_STATUS_OK) {
        goto end;
    }

    status = CTF_MSG_ITER_MEDIUM_STATUS_OK;

end:
    return status;
}

static enum ctf_msg_iter_medium_status medop_group_switch_packet(void *void_data)
{
    struct ctf_fs_ds_group_medops_data *data = (struct ctf_fs_ds_group_medops_data *) void_data;
    struct ctf_fs_ds_index_entry *index_entry;
    enum ctf_msg_iter_medium_status status;

    /* If we have gone through all index entries, we are done. */
    if (data->next_index_entry_index >= data->ds_file_group->index->entries.size()) {
        status = CTF_MSG_ITER_MEDIUM_STATUS_EOF;
        goto end;
    }

    /*
     * Otherwise, look up the next index entry / packet and prepare it
     *  for reading.
     */
    index_entry = data->ds_file_group->index->entries[data->next_index_entry_index].get();

    status = ctf_fs_ds_group_medops_set_file(data, index_entry);
    if (status != CTF_MSG_ITER_MEDIUM_STATUS_OK) {
        goto end;
    }

    data->next_index_entry_index++;

    status = CTF_MSG_ITER_MEDIUM_STATUS_OK;
end:
    return status;
}

void ctf_fs_ds_group_medops_data_deleter::operator()(ctf_fs_ds_group_medops_data *data) noexcept
{
    delete data;
}

enum ctf_msg_iter_medium_status ctf_fs_ds_group_medops_data_create(
    struct ctf_fs_ds_file_group *ds_file_group, bt_self_message_iterator *self_msg_iter,
    const bt2c::Logger& parentLogger, ctf_fs_ds_group_medops_data_up& out)
{
    BT_ASSERT(self_msg_iter);
    BT_ASSERT(ds_file_group);
    BT_ASSERT(ds_file_group->index);
    BT_ASSERT(!ds_file_group->index->entries.empty());

    out.reset(new ctf_fs_ds_group_medops_data {parentLogger});

    out->ds_file_group = ds_file_group;
    out->self_msg_iter = self_msg_iter;

    /*
     * No need to prepare the first file.  ctf_msg_iter will call
     * switch_packet before reading the first packet, it will be
     * done then.
     */

    return CTF_MSG_ITER_MEDIUM_STATUS_OK;
}

void ctf_fs_ds_group_medops_data_reset(struct ctf_fs_ds_group_medops_data *data)
{
    data->next_index_entry_index = 0;
}

struct ctf_msg_iter_medium_ops ctf_fs_ds_group_medops = {
    .request_bytes = medop_group_request_bytes,

    /*
     * We don't support seeking using this medops.  It would probably be
     * possible, but it's not needed at the moment.
     */
    .seek = NULL,

    .switch_packet = medop_group_switch_packet,
    .borrow_stream = medop_group_borrow_stream,
};

static ctf_fs_ds_index_entry::UP ctf_fs_ds_index_entry_create(const bt2c::DataLen offset,
                                                              const bt2c::DataLen packetSize)
{
    ctf_fs_ds_index_entry::UP entry = bt2s::make_unique<ctf_fs_ds_index_entry>(offset, packetSize);

    entry->packet_seq_num = UINT64_MAX;

    return entry;
}

static int convert_cycles_to_ns(struct ctf_clock_class *clock_class, uint64_t cycles, int64_t *ns)
{
    return bt_util_clock_cycles_to_ns_from_origin(cycles, clock_class->frequency,
                                                  clock_class->offset_seconds,
                                                  clock_class->offset_cycles, ns);
}

static ctf_fs_ds_index::UP build_index_from_idx_file(struct ctf_fs_ds_file *ds_file,
                                                     struct ctf_fs_ds_file_info *file_info,
                                                     struct ctf_msg_iter *msg_iter)
{
    int ret;
    gchar *directory = NULL;
    gchar *basename = NULL;
    GString *index_basename = NULL;
    gchar *index_file_path = NULL;
    GMappedFile *mapped_file = NULL;
    gsize filesize;
    const char *mmap_begin = NULL, *file_pos = NULL;
    const struct ctf_packet_index_file_hdr *header = NULL;
    ctf_fs_ds_index::UP index;
    ctf_fs_ds_index_entry::UP index_entry;
    ctf_fs_ds_index_entry *prev_index_entry = NULL;
    auto totalPacketsSize = bt2c::DataLen::fromBytes(0);
    size_t file_index_entry_size;
    size_t file_entry_count;
    size_t i;
    struct ctf_stream_class *sc;
    struct ctf_msg_iter_packet_properties props;
    uint32_t version_major, version_minor;

    BT_CPPLOGI_SPEC(ds_file->logger, "Building index from .idx file of stream file {}",
                    ds_file->file->path);
    ret = ctf_msg_iter_get_packet_properties(msg_iter, &props);
    if (ret) {
        BT_CPPLOGI_STR_SPEC(ds_file->logger,
                            "Cannot read first packet's header and context fields.");
        goto error;
    }

    sc = ctf_trace_class_borrow_stream_class_by_id(ds_file->metadata->tc, props.stream_class_id);
    BT_ASSERT(sc);
    if (!sc->default_clock_class) {
        BT_CPPLOGI_STR_SPEC(ds_file->logger, "Cannot find stream class's default clock class.");
        goto error;
    }

    /* Look for index file in relative path index/name.idx. */
    basename = g_path_get_basename(ds_file->file->path.c_str());
    if (!basename) {
        BT_CPPLOGE_SPEC(ds_file->logger, "Cannot get the basename of datastream file {}",
                        ds_file->file->path);
        goto error;
    }

    directory = g_path_get_dirname(ds_file->file->path.c_str());
    if (!directory) {
        BT_CPPLOGE_SPEC(ds_file->logger, "Cannot get dirname of datastream file {}",
                        ds_file->file->path);
        goto error;
    }

    index_basename = g_string_new(basename);
    if (!index_basename) {
        BT_CPPLOGE_STR_SPEC(ds_file->logger, "Cannot allocate index file basename string");
        goto error;
    }

    g_string_append(index_basename, ".idx");
    index_file_path = g_build_filename(directory, "index", index_basename->str, NULL);
    mapped_file = g_mapped_file_new(index_file_path, FALSE, NULL);
    if (!mapped_file) {
        BT_CPPLOGD_SPEC(ds_file->logger, "Cannot create new mapped file {}", index_file_path);
        goto error;
    }

    /*
     * The g_mapped_file API limits us to 4GB files on 32-bit.
     * Traces with such large indexes have never been seen in the wild,
     * but this would need to be adjusted to support them.
     */
    filesize = g_mapped_file_get_length(mapped_file);
    if (filesize < sizeof(*header)) {
        BT_CPPLOGW_SPEC(ds_file->logger,
                        "Invalid LTTng trace index file: "
                        "file size ({} bytes) < header size ({} bytes)",
                        filesize, sizeof(*header));
        goto error;
    }

    mmap_begin = g_mapped_file_get_contents(mapped_file);
    header = (struct ctf_packet_index_file_hdr *) mmap_begin;

    file_pos = g_mapped_file_get_contents(mapped_file) + sizeof(*header);
    if (be32toh(header->magic) != CTF_INDEX_MAGIC) {
        BT_CPPLOGW_STR_SPEC(ds_file->logger,
                            "Invalid LTTng trace index: \"magic\" field validation failed");
        goto error;
    }

    version_major = be32toh(header->index_major);
    version_minor = be32toh(header->index_minor);
    if (version_major != 1) {
        BT_CPPLOGW_SPEC(ds_file->logger, "Unknown LTTng trace index version: major={}, minor={}",
                        version_major, version_minor);
        goto error;
    }

    file_index_entry_size = be32toh(header->packet_index_len);
    if (file_index_entry_size < CTF_INDEX_1_0_SIZE) {
        BT_CPPLOGW_SPEC(
            ds_file->logger,
            "Invalid `packet_index_len` in LTTng trace index file (`packet_index_len` < CTF index 1.0 index entry size): "
            "packet_index_len={}, CTF_INDEX_1_0_SIZE={}",
            file_index_entry_size, CTF_INDEX_1_0_SIZE);
        goto error;
    }

    file_entry_count = (filesize - sizeof(*header)) / file_index_entry_size;
    if ((filesize - sizeof(*header)) % file_index_entry_size) {
        BT_CPPLOGW_SPEC(ds_file->logger,
                        "Invalid LTTng trace index: the index's size after the header "
                        "({} bytes) is not a multiple of the index entry size "
                        "({} bytes)",
                        (filesize - sizeof(*header)), sizeof(*header));
        goto error;
    }

    index = bt2s::make_unique<ctf_fs_ds_index>();

    for (i = 0; i < file_entry_count; i++) {
        struct ctf_packet_index *file_index = (struct ctf_packet_index *) file_pos;
        const auto packetSize = bt2c::DataLen::fromBits(be64toh(file_index->packet_size));

        if (packetSize.hasExtraBits()) {
            BT_CPPLOGW_SPEC(ds_file->logger,
                            "Invalid packet size encountered in LTTng trace index file");
            goto error;
        }

        const auto offset = bt2c::DataLen::fromBytes(be64toh(file_index->offset));

        if (i != 0 && offset < prev_index_entry->offset) {
            BT_CPPLOGW_SPEC(
                ds_file->logger,
                "Invalid, non-monotonic, packet offset encountered in LTTng trace index file: "
                "previous offset={} bytes, current offset={} bytes",
                prev_index_entry->offset.bytes(), offset.bytes());
            goto error;
        }

        index_entry = ctf_fs_ds_index_entry_create(offset, packetSize);
        if (!index_entry) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ds_file->logger,
                                         "Failed to create a ctf_fs_ds_index_entry.");
            goto error;
        }

        /* Set path to stream file. */
        index_entry->path = file_info->path.c_str();

        index_entry->timestamp_begin = be64toh(file_index->timestamp_begin);
        index_entry->timestamp_end = be64toh(file_index->timestamp_end);
        if (index_entry->timestamp_end < index_entry->timestamp_begin) {
            BT_CPPLOGW_SPEC(
                ds_file->logger,
                "Invalid packet time bounds encountered in LTTng trace index file (begin > end): "
                "timestamp_begin={}, timestamp_end={}",
                index_entry->timestamp_begin, index_entry->timestamp_end);
            goto error;
        }

        /* Convert the packet's bound to nanoseconds since Epoch. */
        ret = convert_cycles_to_ns(sc->default_clock_class, index_entry->timestamp_begin,
                                   &index_entry->timestamp_begin_ns);
        if (ret) {
            BT_CPPLOGI_STR_SPEC(
                ds_file->logger,
                "Failed to convert raw timestamp to nanoseconds since Epoch during index parsing");
            goto error;
        }
        ret = convert_cycles_to_ns(sc->default_clock_class, index_entry->timestamp_end,
                                   &index_entry->timestamp_end_ns);
        if (ret) {
            BT_CPPLOGI_STR_SPEC(
                ds_file->logger,
                "Failed to convert raw timestamp to nanoseconds since Epoch during LTTng trace index parsing");
            goto error;
        }

        if (version_minor >= 1) {
            index_entry->packet_seq_num = be64toh(file_index->packet_seq_num);
        }

        totalPacketsSize += packetSize;
        file_pos += file_index_entry_size;

        prev_index_entry = index_entry.get();

        index->entries.emplace_back(std::move(index_entry));
    }

    /* Validate that the index addresses the complete stream. */
    if (ds_file->file->size != totalPacketsSize.bytes()) {
        BT_CPPLOGW_SPEC(ds_file->logger,
                        "Invalid LTTng trace index file; indexed size != stream file size: "
                        "file-size={} bytes, total-packets-size={} bytes",
                        ds_file->file->size, totalPacketsSize.bytes());
        goto error;
    }
end:
    g_free(directory);
    g_free(basename);
    g_free(index_file_path);
    if (index_basename) {
        g_string_free(index_basename, TRUE);
    }
    if (mapped_file) {
        g_mapped_file_unref(mapped_file);
    }
    return index;
error:
    index.reset();
    goto end;
}

static int init_index_entry(struct ctf_fs_ds_index_entry *entry, struct ctf_fs_ds_file *ds_file,
                            struct ctf_msg_iter_packet_properties *props)
{
    int ret = 0;
    struct ctf_stream_class *sc;

    sc = ctf_trace_class_borrow_stream_class_by_id(ds_file->metadata->tc, props->stream_class_id);
    BT_ASSERT(sc);

    if (props->snapshots.beginning_clock != UINT64_C(-1)) {
        entry->timestamp_begin = props->snapshots.beginning_clock;

        /* Convert the packet's bound to nanoseconds since Epoch. */
        ret = convert_cycles_to_ns(sc->default_clock_class, props->snapshots.beginning_clock,
                                   &entry->timestamp_begin_ns);
        if (ret) {
            BT_CPPLOGI_STR_SPEC(ds_file->logger,
                                "Failed to convert raw timestamp to nanoseconds since Epoch.");
            goto end;
        }
    } else {
        entry->timestamp_begin = UINT64_C(-1);
        entry->timestamp_begin_ns = UINT64_C(-1);
    }

    if (props->snapshots.end_clock != UINT64_C(-1)) {
        entry->timestamp_end = props->snapshots.end_clock;

        /* Convert the packet's bound to nanoseconds since Epoch. */
        ret = convert_cycles_to_ns(sc->default_clock_class, props->snapshots.end_clock,
                                   &entry->timestamp_end_ns);
        if (ret) {
            BT_CPPLOGI_STR_SPEC(ds_file->logger,
                                "Failed to convert raw timestamp to nanoseconds since Epoch.");
            goto end;
        }
    } else {
        entry->timestamp_end = UINT64_C(-1);
        entry->timestamp_end_ns = UINT64_C(-1);
    }

end:
    return ret;
}

static ctf_fs_ds_index::UP build_index_from_stream_file(struct ctf_fs_ds_file *ds_file,
                                                        struct ctf_fs_ds_file_info *file_info,
                                                        struct ctf_msg_iter *msg_iter)
{
    int ret;
    enum ctf_msg_iter_status iter_status = CTF_MSG_ITER_STATUS_OK;
    auto currentPacketOffset = bt2c::DataLen::fromBytes(0);

    BT_CPPLOGI_SPEC(ds_file->logger, "Indexing stream file {}", ds_file->file->path);

    ctf_fs_ds_index::UP index = bt2s::make_unique<ctf_fs_ds_index>();

    while (true) {
        struct ctf_msg_iter_packet_properties props;

        if (currentPacketOffset.bytes() > ds_file->file->size) {
            BT_CPPLOGE_STR_SPEC(ds_file->logger,
                                "Unexpected current packet's offset (larger than file).");
            goto error;
        } else if (currentPacketOffset.bytes() == ds_file->file->size) {
            /* No more data */
            break;
        }

        iter_status = ctf_msg_iter_seek(msg_iter, currentPacketOffset.bytes());
        if (iter_status != CTF_MSG_ITER_STATUS_OK) {
            goto error;
        }

        iter_status = ctf_msg_iter_get_packet_properties(msg_iter, &props);
        if (iter_status != CTF_MSG_ITER_STATUS_OK) {
            goto error;
        }

        /*
         * Get the current packet size from the packet header, if set.  Else,
         * assume there is a single packet in the file, so take the file size
         * as the packet size.
         */
        const auto currentPacketSize = props.exp_packet_total_size >= 0 ?
                                           bt2c::DataLen::fromBits(props.exp_packet_total_size) :
                                           bt2c::DataLen::fromBytes(ds_file->file->size);

        if ((currentPacketOffset + currentPacketSize).bytes() > ds_file->file->size) {
            BT_CPPLOGW_SPEC(ds_file->logger,
                            "Invalid packet size reported in file: stream=\"{}\", "
                            "packet-offset-bytes={}, packet-size-bytes={}, "
                            "file-size-bytes={}",
                            ds_file->file->path, currentPacketOffset.bytes(),
                            currentPacketSize.bytes(), ds_file->file->size);
            goto error;
        }

        auto index_entry = ctf_fs_ds_index_entry_create(currentPacketOffset, currentPacketSize);
        if (!index_entry) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(ds_file->logger,
                                         "Failed to create a ctf_fs_ds_index_entry.");
            goto error;
        }

        /* Set path to stream file. */
        index_entry->path = file_info->path.c_str();

        ret = init_index_entry(index_entry.get(), ds_file, &props);
        if (ret) {
            goto error;
        }

        index->entries.emplace_back(std::move(index_entry));

        currentPacketOffset += currentPacketSize;
        BT_CPPLOGD_SPEC(ds_file->logger,
                        "Seeking to next packet: current-packet-offset-bytes={}, "
                        "next-packet-offset-bytes={}",
                        (currentPacketOffset - currentPacketSize).bytes(),
                        currentPacketOffset.bytes());
    }

end:
    return index;

error:
    index.reset();
    goto end;
}

ctf_fs_ds_file::UP ctf_fs_ds_file_create(struct ctf_fs_trace *ctf_fs_trace,
                                         bt2::Stream::Shared stream, const char *path,
                                         const bt2c::Logger& parentLogger)
{
    int ret;
    auto ds_file = bt2s::make_unique<ctf_fs_ds_file>(parentLogger);
    size_t offset_align;

    ds_file->file = bt2s::make_unique<ctf_fs_file>(parentLogger);
    ds_file->stream = std::move(stream);
    ds_file->metadata = ctf_fs_trace->metadata.get();
    ds_file->file->path = path;
    ret = ctf_fs_file_open(ds_file->file.get(), "rb");
    if (ret) {
        goto error;
    }

    offset_align = bt_mmap_get_offset_align_size(static_cast<int>(ds_file->logger.level()));
    ds_file->mmap_max_len = offset_align * 2048;

    goto end;

error:
    /* Do not touch "borrowed" file. */
    ds_file.reset();

end:
    return ds_file;
}

ctf_fs_ds_index::UP ctf_fs_ds_file_build_index(struct ctf_fs_ds_file *ds_file,
                                               struct ctf_fs_ds_file_info *file_info,
                                               struct ctf_msg_iter *msg_iter)
{
    auto index = build_index_from_idx_file(ds_file, file_info, msg_iter);
    if (index) {
        goto end;
    }

    BT_CPPLOGI_SPEC(ds_file->logger, "Failed to build index from .index file; "
                                     "falling back to stream indexing.");
    index = build_index_from_stream_file(ds_file, file_info, msg_iter);
end:
    return index;
}

ctf_fs_ds_file::~ctf_fs_ds_file()
{
    (void) ds_file_munmap(this);
}

ctf_fs_ds_file_info::UP ctf_fs_ds_file_info_create(const char *path, int64_t begin_ns)
{
    ctf_fs_ds_file_info::UP ds_file_info = bt2s::make_unique<ctf_fs_ds_file_info>();

    ds_file_info->path = path;
    ds_file_info->begin_ns = begin_ns;
    return ds_file_info;
}

ctf_fs_ds_file_group::UP ctf_fs_ds_file_group_create(struct ctf_fs_trace *ctf_fs_trace,
                                                     struct ctf_stream_class *sc,
                                                     uint64_t stream_instance_id,
                                                     ctf_fs_ds_index::UP index)
{
    ctf_fs_ds_file_group::UP ds_file_group {new ctf_fs_ds_file_group};

    ds_file_group->index = std::move(index);

    ds_file_group->stream_id = stream_instance_id;
    BT_ASSERT(sc);
    ds_file_group->sc = sc;
    ds_file_group->ctf_fs_trace = ctf_fs_trace;

    return ds_file_group;
}
