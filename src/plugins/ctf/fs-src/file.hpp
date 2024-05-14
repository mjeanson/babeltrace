/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_FS_SRC_FILE_HPP
#define BABELTRACE_PLUGINS_CTF_FS_SRC_FILE_HPP

#include <memory>
#include <string>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/libc-up.hpp"
#include "cpp-common/bt2c/logging.hpp"

struct ctf_fs_file
{
    using UP = std::unique_ptr<ctf_fs_file>;

    explicit ctf_fs_file(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/SRC.CTF.FS/FILE"}
    {
    }

    bt2c::Logger logger;

    std::string path;

    bt2c::FileUP fp;

    off_t size = 0;
};

int ctf_fs_file_open(struct ctf_fs_file *file, const char *mode);

#endif /* BABELTRACE_PLUGINS_CTF_FS_SRC_FILE_HPP */
