/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <sstream>

#include "cpp-common/bt2c/bt2-value-from-json-val.hpp"

#include "utils.hpp"

namespace ctf {
namespace src {

bt2::MapValue::Shared bt2ValueOfObj(const bt2c::JsonObjVal& jsonObjVal, const std::string& key)
{
    if (const auto jsonUserAttrsVal = jsonObjVal[key]) {
        return bt2c::bt2ValueFromJsonVal(*jsonUserAttrsVal)->asMap().shared();
    }

    return bt2::MapValue::Shared {};
}

std::string absFieldLocStr(const FieldLoc& fieldLoc, const FieldLoc::Items::const_iterator end)
{
    std::ostringstream ss;

    BT_ASSERT(fieldLoc.origin());
    ss << '[' << scopeStr(*fieldLoc.origin());

    for (auto it = fieldLoc.begin(); it != end; ++it) {
        BT_ASSERT(*it);
        ss << fmt::format(", `{}`", **it);
    }

    ss << ']';
    return ss.str();
}

} /* namespace src */
} /* namespace ctf */
