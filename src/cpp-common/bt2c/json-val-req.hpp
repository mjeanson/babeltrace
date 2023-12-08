/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_JSON_VAL_REQ_HPP
#define BABELTRACE_CPP_COMMON_BT2C_JSON_VAL_REQ_HPP

#include <memory>
#include <string>
#include <unordered_map>

#include "common/common.h"

#include "json-val.hpp"
#include "val-req.hpp"

namespace bt2c {
namespace internal {

struct JsonValOps final
{
    static ValType valType(const JsonVal& jsonVal) noexcept
    {
        switch (jsonVal.type()) {
        case JsonVal::Type::Null:
            return ValType::Null;
        case JsonVal::Type::Bool:
            return ValType::Bool;
        case JsonVal::Type::SInt:
            return ValType::SInt;
        case JsonVal::Type::UInt:
            return ValType::UInt;
        case JsonVal::Type::Real:
            return ValType::Real;
        case JsonVal::Type::Str:
            return ValType::Str;
        case JsonVal::Type::Array:
            return ValType::Array;
        case JsonVal::Type::Obj:
            return ValType::Obj;
        default:
            bt_common_abort();
        }
    }

    static const char *typeDetStr(const ValType type) noexcept
    {
        switch (type) {
        case ValType::Null:
            return "";
        case ValType::Bool:
        case ValType::SInt:
        case ValType::Real:
        case ValType::Str:
            return "a";
        case ValType::UInt:
        case ValType::Array:
        case ValType::Obj:
            return "an";
        default:
            bt_common_abort();
        }
    }

    static const char *typeStr(const ValType type) noexcept
    {
        switch (type) {
        case ValType::Null:
            return "`null`";
        case ValType::Bool:
            return "boolean";
        case ValType::SInt:
            return "signed integer";
        case ValType::UInt:
            return "unsigned integer";
        case ValType::Real:
            return "real";
        case ValType::Str:
            return "string";
        case ValType::Array:
            return "array";
        case ValType::Obj:
            return "object";
        default:
            bt_common_abort();
        }
    }

    static constexpr const char *objValPropName = "property";

    static const TextLoc& valLoc(const JsonVal& jsonVal) noexcept
    {
        return jsonVal.loc();
    }

    static const JsonUIntVal& asUInt(const JsonVal& jsonVal) noexcept
    {
        return jsonVal.asUInt();
    }

    static const JsonStrVal& asStr(const JsonVal& jsonVal) noexcept
    {
        return jsonVal.asStr();
    }

    static const JsonArrayVal& asArray(const JsonVal& jsonVal) noexcept
    {
        return jsonVal.asArray();
    }

    static const JsonObjVal& asObj(const JsonVal& jsonVal) noexcept
    {
        return jsonVal.asObj();
    }

    template <typename JsonScalarValT>
    using ScalarValRawValT = typename JsonScalarValT::Val;

    template <typename JsonScalarValT>
    static typename JsonScalarValT::Val scalarValRawVal(const JsonScalarValT& jsonVal) noexcept
    {
        return *jsonVal;
    }

    static const std::string& scalarValRawVal(const JsonStrVal& jsonVal) noexcept
    {
        return *jsonVal;
    }

    static std::size_t arrayValSize(const JsonArrayVal& jsonVal) noexcept
    {
        return jsonVal.size();
    }

    static const JsonVal& arrayValElem(const JsonArrayVal& jsonVal,
                                       const std::size_t index) noexcept
    {
        return jsonVal[index];
    }

    static const JsonVal *objValVal(const JsonObjVal& jsonVal, const std::string& key) noexcept
    {
        return jsonVal[key];
    }

    static JsonObjVal::Container::const_iterator objValBegin(const JsonObjVal& jsonVal) noexcept
    {
        return jsonVal.begin();
    }

    static JsonObjVal::Container::const_iterator objValEnd(const JsonObjVal& jsonVal) noexcept
    {
        return jsonVal.end();
    }

    static const std::string& objValItKey(const JsonObjVal::Container::const_iterator& it) noexcept
    {
        return it->first;
    }

    static const JsonVal& objValItVal(const JsonObjVal::Container::const_iterator& it) noexcept
    {
        return *it->second;
    }
};

} /* namespace internal */

/*
 * Value requirement aliases to validate JSON values (`JsonVal`).
 */
using JsonValReq = ValReq<JsonVal, internal::JsonValOps>;
using JsonValHasTypeReq = ValHasTypeReq<JsonVal, internal::JsonValOps>;
using JsonAnyIntValReq = AnyIntValReq<JsonVal, internal::JsonValOps>;
using JsonUIntValReq = UIntValReq<JsonVal, internal::JsonValOps>;
using JsonSIntValReq = SIntValReq<JsonVal, internal::JsonValOps>;

using JsonUIntValInRangeReq =
    IntValInRangeReq<JsonVal, internal::JsonValOps, JsonUIntVal, ValType::UInt>;

using JsonSIntValInRangeReq =
    IntValInRangeReq<JsonVal, internal::JsonValOps, JsonSIntVal, ValType::SInt>;

using JsonBoolValInSetReq =
    ScalarValInSetReq<JsonVal, internal::JsonValOps, JsonBoolVal, ValType::Bool>;

using JsonUIntValInSetReq =
    ScalarValInSetReq<JsonVal, internal::JsonValOps, JsonUIntVal, ValType::UInt>;

using JsonSIntValInSetReq =
    ScalarValInSetReq<JsonVal, internal::JsonValOps, JsonSIntVal, ValType::SInt>;

using JsonStrValInSetReq =
    ScalarValInSetReq<JsonVal, internal::JsonValOps, JsonStrVal, ValType::Str>;

using JsonArrayValReq = ArrayValReq<JsonVal, internal::JsonValOps>;
using JsonObjValPropReq = ObjValPropReq<JsonVal, internal::JsonValOps>;
using JsonObjValReq = ObjValReq<JsonVal, internal::JsonValOps>;

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_JSON_VAL_REQ_HPP */
