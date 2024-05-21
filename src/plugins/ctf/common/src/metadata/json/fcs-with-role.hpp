/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_FCS_WITH_ROLE_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_FCS_WITH_ROLE_HPP

#include <unordered_set>

#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Returns a set of all the field classes having at least one role
 * amongst `roles` and/or the "metadata stream UUID" role if
 * `withMetadataStreamUuidRole` is true for a static-length BLOB
 * field class.
 */
std::unordered_set<const Fc *> fcsWithRole(const Fc& fc, const UIntFieldRoles& roles,
                                           bool withMetadataStreamUuidRole);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_FCS_WITH_ROLE_HPP */
