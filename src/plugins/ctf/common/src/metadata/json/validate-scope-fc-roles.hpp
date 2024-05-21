/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_VALIDATE_SCOPE_FC_ROLES_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_VALIDATE_SCOPE_FC_ROLES_HPP

#include "cpp-common/bt2c/logging.hpp"

#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Validates that:
 *
 * • If any unsigned integer field class within `fc` has one or more
 *   roles, then those roles are part of the `allowedRoles` set.
 *
 * • If any static-length BLOB field class within `fc` has the metadata
 *   stream UUID role, then `allowMetadataStreamUuidRole` is true.
 *
 * Appends one or more causes to the error of the current thread and
 * throws `bt2c::Error` when `fc` is invalid.
 */
void validateScopeFcRoles(const Fc& fc, const UIntFieldRoles& allowedRoles,
                          bool allowMetadataStreamUuidRole, const bt2c::Logger& parentLogger);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_VALIDATE_SCOPE_FC_ROLES_HPP */
