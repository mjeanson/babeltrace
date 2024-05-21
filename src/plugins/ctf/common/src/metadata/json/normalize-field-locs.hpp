/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_NORMALIZE_FIELD_LOCS_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_NORMALIZE_FIELD_LOCS_HPP

#include "cpp-common/bt2c/logging.hpp"

#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Converts all the relative field locations in `scopeFc` into absolute
 * field locations.
 *
 * `scopeFc` is a scope field class for the scope `scope`.
 *
 * ┌────────────────────────────────────────────────────────────────┐
 * │ IMPORTANT: This function doesn't guarantee that the normalized │
 * │ field locations are valid.                                     │
 * └────────────────────────────────────────────────────────────────┘
 *
 * Appends one or more causes to the error of the current thread using
 * and throws `bt2c::Error` when any relative field location in
 * `scopeFc` is invalid.
 */
void normalizeFieldLocs(Fc& scopeFc, Scope scope, const bt2c::Logger& parentLogger);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_NORMALIZE_FIELD_LOCS_HPP */
