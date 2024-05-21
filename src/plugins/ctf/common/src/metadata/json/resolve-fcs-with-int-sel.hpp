/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_RESOLVE_FCS_WITH_INT_SEL_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_RESOLVE_FCS_WITH_INT_SEL_HPP

#include "cpp-common/bt2c/logging.hpp"

#include "../ctf-ir.hpp"

namespace ctf {
namespace src {

/*
 * Replaces all the field classes within `scopeFc` having the type
 * `FcType::OptionalWithUIntSel` or `FcType::VariantWithUIntSel` with
 * the correct versions, keeping their children as is.
 *
 * `scopeFc` is a scope field class for the scope `scope`.
 *
 * Also validates the dynamic-length field classes.
 *
 * This function uses keyFcTypes() behind the scenes, therefore all the
 * preconditions of the latter apply.
 *
 * Appends one or more causes to the error of the current thread and
 * throws `bt2c::Error` when any field class in `scopeFc` is invalid.
 */
void resolveFcsWithIntSel(Fc& scopeFc, Scope scope, const Fc *pktHeaderFc, const Fc *pktCtxFc,
                          const Fc *eventRecordHeaderFc, const Fc *commonEventRecordCtxFc,
                          const Fc *specEventRecordCtxFc, const Fc *eventRecordPayloadFc,
                          const bt2c::Logger& logger);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_RESOLVE_FCS_WITH_INT_SEL_HPP */
