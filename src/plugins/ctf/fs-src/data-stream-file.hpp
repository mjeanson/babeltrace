/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_FS_DS_FILE_H
#define CTF_FS_DS_FILE_H

#include <glib.h>
#include <stdio.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/logging.hpp"

#include "../common/src/msg-iter/msg-iter.hpp"

struct ctf_fs_ds_file_info
{
    /* Owned by this. */
    GString *path = nullptr;

    /* Guaranteed to be set, as opposed to the index. */
    int64_t begin_ns = 0;
};

struct ctf_fs_ds_file
{
    explicit ctf_fs_ds_file(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/DS"}
    {
    }

    bt2c::Logger logger;

    /* Weak */
    struct ctf_fs_metadata *metadata = nullptr;

    /* Owned by this */
    struct ctf_fs_file *file = nullptr;

    /* Owned by this */
    bt_stream *stream = nullptr;

    void *mmap_addr = nullptr;

    /*
     * Max length of chunk to mmap() when updating the current mapping.
     * This value must be page-aligned.
     */
    size_t mmap_max_len = 0;

    /* Length of the current mapping. Never exceeds the file's length. */
    size_t mmap_len = 0;

    /* Offset in the file where the current mapping starts. */
    off_t mmap_offset_in_file = 0;

    /*
     * Offset, in the current mapping, of the address to return on the next
     * request.
     */
    off_t request_offset_in_mapping = 0;
};

struct ctf_fs_ds_file *ctf_fs_ds_file_create(struct ctf_fs_trace *ctf_fs_trace, bt_stream *stream,
                                             const char *path, const bt2c::Logger& logger);

void ctf_fs_ds_file_destroy(struct ctf_fs_ds_file *stream);

struct ctf_fs_ds_index *ctf_fs_ds_file_build_index(struct ctf_fs_ds_file *ds_file,
                                                   struct ctf_fs_ds_file_info *ds_file_info,
                                                   struct ctf_msg_iter *msg_iter);

struct ctf_fs_ds_index *ctf_fs_ds_index_create(const bt2c::Logger& logger);

void ctf_fs_ds_index_destroy(struct ctf_fs_ds_index *index);

/*
 * Medium operations to iterate on a single ctf_fs_ds_file.
 *
 * The data pointer when using this must be a pointer to the ctf_fs_ds_file.
 */
extern struct ctf_msg_iter_medium_ops ctf_fs_ds_file_medops;

/*
 * Medium operations to iterate on the packet of a ctf_fs_ds_group.
 *
 * The iteration is done based on the index of the group.
 *
 * The data pointer when using these medops must be a pointer to a ctf_fs_ds
 * group_medops_data structure.
 */
extern struct ctf_msg_iter_medium_ops ctf_fs_ds_group_medops;

enum ctf_msg_iter_medium_status ctf_fs_ds_group_medops_data_create(
    struct ctf_fs_ds_file_group *ds_file_group, bt_self_message_iterator *self_msg_iter,
    const bt2c::Logger& logger, struct ctf_fs_ds_group_medops_data **out);

void ctf_fs_ds_group_medops_data_reset(struct ctf_fs_ds_group_medops_data *data);

void ctf_fs_ds_group_medops_data_destroy(struct ctf_fs_ds_group_medops_data *data);

#endif /* CTF_FS_DS_FILE_H */
