/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#include "common/assert.h"

#include "../common/src/metadata/tsdl/decoder.hpp"
#include "file.hpp"
#include "fs.hpp"
#include "metadata.hpp"

FILE *ctf_fs_metadata_open_file(const char *trace_path, const bt2c::Logger& logger)
{
    GString *metadata_path;
    FILE *fp = NULL;

    metadata_path = g_string_new(trace_path);
    if (!metadata_path) {
        goto end;
    }

    g_string_append(metadata_path, G_DIR_SEPARATOR_S CTF_FS_METADATA_FILENAME);
    fp = fopen(metadata_path->str, "rb");
    if (!fp) {
        BT_CPPLOGE_ERRNO_APPEND_CAUSE_SPEC(logger, "Failed to open metadata file", ": path=\"{}\"",
                                           metadata_path->str);
    }

    g_string_free(metadata_path, TRUE);

end:
    return fp;
}

static ctf_fs_file::UP get_file(const bt2c::CStringView trace_path, const bt2c::Logger& logger)
{
    auto file = ctf_fs_file_create(logger);

    if (!file) {
        goto error;
    }

    file->path = fmt::format("{}" G_DIR_SEPARATOR_S CTF_FS_METADATA_FILENAME, trace_path);

    if (ctf_fs_file_open(file.get(), "rb")) {
        goto error;
    }

    goto end;

error:
    file.reset();

end:
    return file;
}

int ctf_fs_metadata_set_trace_class(bt_self_component *self_comp, struct ctf_fs_trace *ctf_fs_trace,
                                    const ctf::src::ClkClsCfg& clkClsCfg)
{
    int ret = 0;
    ctf_metadata_decoder_config decoder_config {ctf_fs_trace->logger};

    decoder_config.self_comp = self_comp;
    decoder_config.clkClsCfg = clkClsCfg;
    decoder_config.create_trace_class = true;

    const auto file = get_file(ctf_fs_trace->path, ctf_fs_trace->logger);
    if (!file) {
        BT_CPPLOGE_SPEC(ctf_fs_trace->logger, "Cannot create metadata file object.");
        ret = -1;
        goto end;
    }

    ctf_fs_trace->metadata->decoder = ctf_metadata_decoder_create(&decoder_config);
    if (!ctf_fs_trace->metadata->decoder) {
        BT_CPPLOGE_SPEC(ctf_fs_trace->logger, "Cannot create metadata decoder object.");
        ret = -1;
        goto end;
    }

    ret =
        ctf_metadata_decoder_append_content(ctf_fs_trace->metadata->decoder.get(), file->fp.get());
    if (ret) {
        BT_CPPLOGE_SPEC(ctf_fs_trace->logger, "Cannot update metadata decoder's content.");
        goto end;
    }

    ctf_fs_trace->metadata->trace_class =
        ctf_metadata_decoder_get_ir_trace_class(ctf_fs_trace->metadata->decoder.get());
    BT_ASSERT(!self_comp || ctf_fs_trace->metadata->trace_class);

    ctf_fs_trace->metadata->tc =
        ctf_metadata_decoder_borrow_ctf_trace_class(ctf_fs_trace->metadata->decoder.get());
    BT_ASSERT(ctf_fs_trace->metadata->tc);

end:
    return ret;
}
