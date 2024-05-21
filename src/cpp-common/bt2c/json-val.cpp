/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <algorithm>

#include "common/assert.h"
#include "cpp-common/bt2s/make-unique.hpp"

#include "json-val.hpp"

namespace bt2c {

JsonVal::JsonVal(const Type type, TextLoc&& loc) noexcept : _mType {type}, _mLoc {std::move(loc)}
{
}

const JsonNullVal& JsonVal::asNull() const noexcept
{
    BT_ASSERT_DBG(this->isNull());
    return static_cast<const JsonNullVal&>(*this);
}

const JsonBoolVal& JsonVal::asBool() const noexcept
{
    BT_ASSERT_DBG(this->isBool());
    return static_cast<const JsonBoolVal&>(*this);
}

const JsonSIntVal& JsonVal::asSInt() const noexcept
{
    BT_ASSERT_DBG(this->isSInt());
    return static_cast<const JsonSIntVal&>(*this);
}

const JsonUIntVal& JsonVal::asUInt() const noexcept
{
    BT_ASSERT_DBG(this->isUInt());
    return static_cast<const JsonUIntVal&>(*this);
}

const JsonRealVal& JsonVal::asReal() const noexcept
{
    BT_ASSERT_DBG(this->isReal());
    return static_cast<const JsonRealVal&>(*this);
}

const JsonStrVal& JsonVal::asStr() const noexcept
{
    BT_ASSERT_DBG(this->isStr());
    return static_cast<const JsonStrVal&>(*this);
}

const JsonArrayVal& JsonVal::asArray() const noexcept
{
    BT_ASSERT_DBG(this->isArray());
    return static_cast<const JsonArrayVal&>(*this);
}

const JsonObjVal& JsonVal::asObj() const noexcept
{
    BT_ASSERT_DBG(this->isObj());
    return static_cast<const JsonObjVal&>(*this);
}

void JsonVal::accept(JsonValVisitor& visitor) const
{
    this->_accept(visitor);
}

JsonNullVal::JsonNullVal(TextLoc loc) noexcept : JsonVal {Type::Null, std::move(loc)}
{
}

void JsonNullVal::_accept(JsonValVisitor& visitor) const
{
    visitor.visit(*this);
}

#ifdef BT_DEBUG_MODE

namespace {

/*
 * Returns `true` if no JSON value unique pointer within `vals` is
 * `nullptr`.
 *
 * `getValueFunc` is a function which accepts a
 * `ContainerT::const_reference` and returns a `const` reference of the
 * contained JSON value unique pointer.
 */
template <typename ContainerT, typename GetValueFuncT>
bool valsNotNull(const ContainerT& vals, GetValueFuncT&& getValueFunc)
{
    return std::all_of(vals.begin(), vals.end(),
                       [&getValueFunc](typename ContainerT::const_reference elem) {
                           return static_cast<bool>(getValueFunc(elem));
                       });
}

} /* namespace */

#endif /* BT_DEBUG_MODE */

JsonArrayVal::JsonArrayVal(Container&& vals, TextLoc loc) :
    JsonCompoundVal {std::move(vals), std::move(loc)}
{
#ifdef BT_DEBUG_MODE
    BT_ASSERT_DBG(valsNotNull(_mVals, [](Container::const_reference elem) -> const JsonVal::UP& {
        return elem;
    }));
#endif
}

void JsonArrayVal::_accept(JsonValVisitor& visitor) const
{
    visitor.visit(*this);
}

JsonObjVal::JsonObjVal(Container&& vals, TextLoc loc) :
    JsonCompoundVal {std::move(vals), std::move(loc)}
{
#ifdef BT_DEBUG_MODE
    BT_ASSERT_DBG(valsNotNull(_mVals, [](Container::const_reference elem) -> const JsonVal::UP& {
        return elem.second;
    }));
#endif
}

void JsonObjVal::_accept(JsonValVisitor& visitor) const
{
    visitor.visit(*this);
}

JsonNullVal::UP createJsonVal(TextLoc loc)
{
    return bt2s::make_unique<const JsonNullVal>(std::move(loc));
}

JsonBoolVal::UP createJsonVal(const bool val, TextLoc loc)
{
    return bt2s::make_unique<const JsonBoolVal>(val, std::move(loc));
}

JsonSIntVal::UP createJsonVal(const long long val, TextLoc loc)
{
    return bt2s::make_unique<const JsonSIntVal>(val, std::move(loc));
}

JsonUIntVal::UP createJsonVal(const unsigned long long val, TextLoc loc)
{
    return bt2s::make_unique<const JsonUIntVal>(val, std::move(loc));
}

JsonRealVal::UP createJsonVal(const double val, TextLoc loc)
{
    return bt2s::make_unique<const JsonRealVal>(val, std::move(loc));
}

JsonStrVal::UP createJsonVal(std::string val, TextLoc loc)
{
    return bt2s::make_unique<const JsonStrVal>(std::move(val), std::move(loc));
}

JsonArrayVal::UP createJsonVal(JsonArrayVal::Container&& vals, TextLoc loc)
{
    return bt2s::make_unique<const JsonArrayVal>(std::move(vals), std::move(loc));
}

JsonObjVal::UP createJsonVal(JsonObjVal::Container&& vals, TextLoc loc)
{
    return bt2s::make_unique<const JsonObjVal>(std::move(vals), std::move(loc));
}

} /* namespace bt2c */
