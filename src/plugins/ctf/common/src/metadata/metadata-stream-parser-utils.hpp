/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022-2024 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP

#include <memory>

#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/logging.hpp"

#include "../clk-cls-cfg.hpp"
#include "metadata-stream-parser.hpp"

namespace ctf {
namespace src {

enum class MetadataStreamMajorVersion
{
    V1 = 1,
    V2,
};

/*
 * Returns the major CTF version (1 or 2) of the metadata stream
 * in `buffer`.
 */
MetadataStreamMajorVersion getMetadataStreamMajorVersion(bt2c::ConstBytes buffer) noexcept;

/*
 * Creates and returns a CTF metadata stream parser of which the
 * concrete class depends on `majorVersion`.
 *
 * Forwards other parameters to the CTF metadata stream
 * parser constructor.
 */
std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(MetadataStreamMajorVersion majorVersion,
                           bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                           const ClkClsCfg& clkClsCfg, const bt2c::Logger& parentLogger);

/*
 * Creates and returns a CTF metadata stream parser of which the
 * concrete class depends on the first byte of `buffer`, the beginning
 * of the metadata stream.
 *
 * Forwards other parameters to the CTF metadata stream
 * parser constructor.
 */
std::unique_ptr<MetadataStreamParser>
createMetadataStreamParser(bt2c::ConstBytes buffer,
                           bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                           const ClkClsCfg& clkClsCfg, const bt2c::Logger& parentLogger);

/*
 * Parses the metadata stream in `buffer` using a parser of which the
 * concrete class depends on the first byte of `buffer`, the beginning
 * of the metadata stream.
 *
 * Forwards other parameters to the CTF metadata stream
 * parser constructor.
 */
MetadataStreamParser::ParseRet
parseMetadataStream(bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                    const ClkClsCfg& clkClsCfg, bt2c::ConstBytes buffer,
                    const bt2c::Logger& parentLogger);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_METADATA_STREAM_PARSER_UTILS_HPP */
