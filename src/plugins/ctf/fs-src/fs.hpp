/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 *
 * BabelTrace - CTF on File System Component
 */

#ifndef BABELTRACE_PLUGIN_CTF_FS_H
#define BABELTRACE_PLUGIN_CTF_FS_H

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/glib-up.hpp"
#include "cpp-common/bt2c/logging.hpp"

#include "data-stream-file.hpp"
#include "plugins/ctf/common/src/metadata/tsdl/decoder.hpp"

extern bool ctf_fs_debug;

struct ctf_fs_metadata
{
    /* Owned by this */
    ctf_metadata_decoder_up decoder;

    /* Owned by this */
    bt_trace_class *trace_class = nullptr;

    /* Weak (owned by `decoder` above) */
    struct ctf_trace_class *tc = nullptr;

    /* Owned by this */
    char *text = nullptr;

    int bo = 0;
};

struct ctf_fs_trace_deleter
{
    void operator()(ctf_fs_trace *) noexcept;
};

struct ctf_fs_trace
{
    using UP = std::unique_ptr<ctf_fs_trace, ctf_fs_trace_deleter>;

    explicit ctf_fs_trace(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/TRACE"}
    {
    }

    bt2c::Logger logger;

    /* Owned by this */
    struct ctf_fs_metadata *metadata = nullptr;

    /* Owned by this */
    bt_trace *trace = nullptr;

    std::vector<ctf_fs_ds_file_group::UP> ds_file_groups;

    /* Owned by this */
    GString *path = nullptr;

    /* Next automatic stream ID when not provided by packet header */
    uint64_t next_stream_id = 0;
};

struct ctf_fs_port_data
{
    using UP = std::unique_ptr<ctf_fs_port_data>;

    /* Weak, belongs to ctf_fs_trace */
    struct ctf_fs_ds_file_group *ds_file_group = nullptr;

    /* Weak */
    struct ctf_fs_component *ctf_fs = nullptr;
};

struct ctf_fs_component_deleter
{
    void operator()(ctf_fs_component *);
};

struct ctf_fs_component
{
    using UP = std::unique_ptr<ctf_fs_component, ctf_fs_component_deleter>;

    explicit ctf_fs_component(const bt2c::Logger& parentLogger) noexcept :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/COMP"}
    {
    }

    bt2c::Logger logger;

    std::vector<ctf_fs_port_data::UP> port_data;

    ctf_fs_trace::UP trace;

    ctf::src::ClkClsCfg clkClsCfg;
};

struct ctf_fs_msg_iter_data
{
    explicit ctf_fs_msg_iter_data(bt_self_message_iterator *selfMsgIter) :
        self_msg_iter {selfMsgIter}, logger {bt2::SelfMessageIterator {self_msg_iter},
                                             "PLUGIN/SRC.CTF.FS/MSG-ITER"}
    {
    }

    /* Weak */
    bt_self_message_iterator *self_msg_iter = nullptr;

    bt2c::Logger logger;

    /* Weak, belongs to ctf_fs_trace */
    struct ctf_fs_ds_file_group *ds_file_group = nullptr;

    /* Owned by this */
    struct ctf_msg_iter *msg_iter = nullptr;

    /*
     * Saved error.  If we hit an error in the _next method, but have some
     * messages ready to return, we save the error here and return it on
     * the next _next call.
     */
    bt_message_iterator_class_next_method_status next_saved_status =
        BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
    const struct bt_error *next_saved_error = nullptr;

    struct ctf_fs_ds_group_medops_data *msg_iter_medops_data = nullptr;
};

bt_component_class_initialize_method_status
ctf_fs_init(bt_self_component_source *source, bt_self_component_source_configuration *config,
            const bt_value *params, void *init_method_data);

void ctf_fs_finalize(bt_self_component_source *component);

bt_component_class_query_method_status ctf_fs_query(bt_self_component_class_source *comp_class,
                                                    bt_private_query_executor *priv_query_exec,
                                                    const char *object, const bt_value *params,
                                                    void *method_data, const bt_value **result);

bt_message_iterator_class_initialize_method_status
ctf_fs_iterator_init(bt_self_message_iterator *self_msg_iter,
                     bt_self_message_iterator_configuration *config,
                     bt_self_component_port_output *self_port);

void ctf_fs_iterator_finalize(bt_self_message_iterator *it);

bt_message_iterator_class_next_method_status
ctf_fs_iterator_next(bt_self_message_iterator *iterator, bt_message_array_const msgs,
                     uint64_t capacity, uint64_t *count);

bt_message_iterator_class_seek_beginning_method_status
ctf_fs_iterator_seek_beginning(bt_self_message_iterator *message_iterator);

/* Create and initialize a new, empty ctf_fs_component. */

ctf_fs_component::UP ctf_fs_component_create(const bt2c::Logger& parentLogger);

/*
 * Create one `struct ctf_fs_trace` from one trace, or multiple traces sharing
 * the same UUID.
 *
 * `paths_value` must be an array of strings,
 *
 * The created `struct ctf_fs_trace` is assigned to `ctf_fs->trace`.
 *
 * `self_comp` and `self_comp_class` are used for logging, only one of them
 * should be set.
 */

int ctf_fs_component_create_ctf_fs_trace(struct ctf_fs_component *ctf_fs,
                                         const bt_value *paths_value,
                                         const bt_value *trace_name_value,
                                         bt_self_component *selfComp);

/* Free `ctf_fs` and everything it owns. */

void ctf_fs_destroy(struct ctf_fs_component *ctf_fs);

/*
 * Read and validate parameters taken by the src.ctf.fs plugin.
 *
 *  - The mandatory `paths` parameter is returned in `*paths`.
 *  - The optional `clock-class-offset-s` and `clock-class-offset-ns`, if
 *    present, are recorded in the `ctf_fs` structure.
 *  - The optional `trace-name` parameter is returned in `*trace_name` if
 *    present, else `*trace_name` is set to NULL.
 *
 * `self_comp` and `self_comp_class` are used for logging, only one of them
 * should be set.
 *
 * Return true on success, false if any parameter didn't pass validation.
 */

bool read_src_fs_parameters(const bt_value *params, const bt_value **paths,
                            const bt_value **trace_name, struct ctf_fs_component *ctf_fs);

/*
 * Generate the port name to be used for a given data stream file group.
 */

bt2c::GCharUP ctf_fs_make_port_name(struct ctf_fs_ds_file_group *ds_file_group);

#endif /* BABELTRACE_PLUGIN_CTF_FS_H */
