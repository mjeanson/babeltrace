/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "ctf-ir.hpp"

namespace ctf {
namespace ir {

const char * const ClkOrigin::_unixEpochNs = "babeltrace.org,2020";
const char * const ClkOrigin::_unixEpochName = "unix-epoch";
const char * const ClkOrigin::_unixEpochUid = "";
const char * const defaultBlobMediaType = "application/octet-stream";

} /* namespace ir */
} /* namespace ctf */
