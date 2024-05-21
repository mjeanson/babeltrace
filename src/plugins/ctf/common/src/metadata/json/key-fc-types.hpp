/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_KEY_FC_TYPES_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_KEY_FC_TYPES_HPP

#include <unordered_map>

#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/vendor/wise-enum/wise_enum.h"

#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/* clang-format off */

/* Key (length/selector) field class type */
WISE_ENUM_CLASS(KeyFcType,
    Bool,
    UInt,
    SInt
)

/* clang-format on */

/* Map of dependent field class to key field class type */
using KeyFcTypes = std::unordered_map<const Fc *, KeyFcType>;

/*
 * Returns the (validated) key types of all the dependent field classes
 * within `scopeFc`.
 *
 * `scopeFc` is a scope field class for the scope `scope`.
 *
 * `pktHeaderFc`, `pktCtxFc`, `eventRecordHeaderFc`,
 * `commonEventRecordCtxFc`, `specEventRecordCtxFc`, and
 * `eventRecordPayloadFc` are the current packet header, packet context,
 * event record header, common event record context, specific event
 * record context, and event record payload field classes. Any of them
 * may be `nullptr`.
 *
 * The field locations within `scopeFc` must be absolute.
 *
 * Appends one or more causes to the error of the current thread and
 * throws `bt2c::Error` when any field location in `scopeFc` is invalid.
 */
KeyFcTypes keyFcTypes(const Fc& scopeFc, Scope scope, const Fc *pktHeaderFc, const Fc *pktCtxFc,
                      const Fc *eventRecordHeaderFc, const Fc *commonEventRecordCtxFc,
                      const Fc *specEventRecordCtxFc, const Fc *eventRecordPayloadFc,
                      const bt2c::Logger& parentLogger);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_KEY_FC_TYPES_HPP */
