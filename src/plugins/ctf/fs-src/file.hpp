/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef CTF_FS_FILE_H
#define CTF_FS_FILE_H

#include <babeltrace2/babeltrace.h>

void ctf_fs_file_destroy(struct ctf_fs_file *file);

struct ctf_fs_file *ctf_fs_file_create(bt_logging_level log_level, bt_self_component *self_comp);

int ctf_fs_file_open(struct ctf_fs_file *file, const char *mode);

#endif /* CTF_FS_FILE_H */
