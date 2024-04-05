/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_FS_FILE_H
#define CTF_FS_FILE_H

#include <memory>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/logging.hpp"

struct ctf_fs_file_deleter
{
    void operator()(struct ctf_fs_file *file) noexcept;
};

struct ctf_fs_file
{
    using UP = std::unique_ptr<ctf_fs_file, ctf_fs_file_deleter>;

    explicit ctf_fs_file(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/FILE"}
    {
    }

    bt2c::Logger logger;

    /* Owned by this */
    GString *path = nullptr;

    /* Owned by this */
    FILE *fp = nullptr;

    off_t size = 0;
};

void ctf_fs_file_destroy(struct ctf_fs_file *file);

ctf_fs_file::UP ctf_fs_file_create(const bt2c::Logger& parentLogger);

int ctf_fs_file_open(struct ctf_fs_file *file, const char *mode);

#endif /* CTF_FS_FILE_H */
