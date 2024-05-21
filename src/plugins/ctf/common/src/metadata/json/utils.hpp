/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_UTILS_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_UTILS_HPP

#include <string>

#include "common/common.h"
#include "cpp-common/bt2/value.hpp"
#include "cpp-common/bt2c/json-val.hpp"

#include "../ctf-ir.hpp"
#include "strings.hpp"

namespace ctf {
namespace src {

/*
 * Returns the object of the JSON object value `jsonObjVal` having the
 * key `key` as a libbabeltrace2 value object, or `bt2s::nullopt` if
 * there's no such key.
 */
bt2::MapValue::Shared bt2ValueOfObj(const bt2c::JsonObjVal& jsonObjVal, const std::string& key);

/*
 * Returns the attributes of the JSON object value `jsonObjVal`, or
 * `bt2s::nullopt` if there's no such property.
 */
inline bt2::MapValue::Shared attrsOfObj(const bt2c::JsonObjVal& jsonObjVal)
{
    return bt2ValueOfObj(jsonObjVal, jsonstr::attrs);
}

/*
 * Returns the raw integer value from the JSON unsigned or signed
 * integer value `jsonIntVal`, casted as `ValT`.
 */
template <typename ValT>
ValT rawIntValFromJsonIntVal(const bt2c::JsonVal& jsonIntVal) noexcept
{
    if (jsonIntVal.isUInt()) {
        return static_cast<ValT>(*jsonIntVal.asUInt());
    } else {
        return static_cast<ValT>(*jsonIntVal.asSInt());
    }
}

/*
 * Returns the optional raw string value from the property named
 * `propName` within `jsonObjVal`.
 */
inline bt2s::optional<std::string> optStrOfObj(const bt2c::JsonObjVal& jsonObjVal,
                                               const char * const propName)
{
    const auto jsonVal = jsonObjVal[propName];

    if (jsonVal) {
        return *jsonVal->asStr();
    }

    return bt2s::nullopt;
}

inline const char *scopeStr(const Scope scope) noexcept
{
    switch (scope) {
    case Scope::PktHeader:
        return "packet header";
    case Scope::PktCtx:
        return "packet context";
    case Scope::EventRecordHeader:
        return "event record header";
    case Scope::CommonEventRecordCtx:
        return "common event record context";
    case Scope::SpecEventRecordCtx:
        return "specific event record context";
    case Scope::EventRecordPayload:
        return "event record payload";
    default:
        bt_common_abort();
    }
}

/*
 * Returns a string representation of `fieldLoc`, considering all its
 * path items until `end` (excluded).
 *
 * `fieldLoc` must be an absolute field location.
 */
std::string absFieldLocStr(const FieldLoc& fieldLoc, FieldLoc::Items::const_iterator end);

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_JSON_UTILS_HPP */
