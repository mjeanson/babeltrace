/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Efficios Inc.
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_DECODER_PACKETIZED_FILE_STREAM_TO_BUF_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_DECODER_PACKETIZED_FILE_STREAM_TO_BUF_HPP

#include <cstdio>

#include <stdint.h>

#include <babeltrace2/babeltrace.h>

namespace bt2c {

class Logger;

} /* namespace bt2c */

int ctf_metadata_decoder_packetized_file_stream_to_buf(FILE *fp, char **buf, int byte_order,
                                                       bool *is_uuid_set, uint8_t *uuid,
                                                       const bt2c::Logger& parentLogger);

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_DECODER_PACKETIZED_FILE_STREAM_TO_BUF_HPP */
