/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_JSON_VAL_HPP
#define BABELTRACE_CPP_COMMON_BT2C_JSON_VAL_HPP

#include <cstdlib>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/assert.h"

#include "text-loc.hpp"

namespace bt2c {

/*
 * Type of JSON value.
 */
enum class JsonValType
{
    Null,
    Bool,
    SInt,
    UInt,
    Real,
    Str,
    Array,
    Obj,
};

class JsonNullVal;

template <typename, JsonValType>
class JsonScalarVal;

/*
 * JSON boolean value.
 */
using JsonBoolVal = JsonScalarVal<bool, JsonValType::Bool>;

/*
 * JSON signed integer value.
 */
using JsonSIntVal = JsonScalarVal<long long, JsonValType::SInt>;

/*
 * JSON unsigned integer value.
 */
using JsonUIntVal = JsonScalarVal<unsigned long long, JsonValType::UInt>;

/*
 * JSON real number value.
 */
using JsonRealVal = JsonScalarVal<double, JsonValType::Real>;

/*
 * JSON string value.
 */
using JsonStrVal = JsonScalarVal<std::string, JsonValType::Str>;

class JsonArrayVal;
class JsonObjVal;

/*
 * Visitor of JSON value.
 */
class JsonValVisitor
{
protected:
    explicit JsonValVisitor() = default;

public:
    virtual ~JsonValVisitor() = default;

    virtual void visit(const JsonNullVal&)
    {
    }

    virtual void visit(const JsonBoolVal&)
    {
    }

    virtual void visit(const JsonSIntVal&)
    {
    }

    virtual void visit(const JsonUIntVal&)
    {
    }

    virtual void visit(const JsonRealVal&)
    {
    }

    virtual void visit(const JsonStrVal&)
    {
    }

    virtual void visit(const JsonArrayVal&)
    {
    }

    virtual void visit(const JsonObjVal&)
    {
    }
};

/*
 * Abstract base class for any JSON value.
 */
class JsonVal
{
public:
    /* Useful local alias */
    using Type = JsonValType;

    /* Unique pointer to constant JSON value */
    using UP = std::unique_ptr<const JsonVal>;

protected:
    /*
     * Builds a JSON value of type `type` located at `loc`.
     */
    explicit JsonVal(Type type, TextLoc&& loc) noexcept;

public:
    /* Deleted copy/move constructors/operators to simplify */
    JsonVal(const JsonVal&) = delete;
    JsonVal(JsonVal&&) = delete;
    JsonVal& operator=(const JsonVal&) = delete;
    JsonVal& operator=(JsonVal&&) = delete;

    virtual ~JsonVal() = default;

    /*
     * Type of this JSON value.
     */
    Type type() const noexcept
    {
        return _mType;
    }

    /*
     * Location of this JSON value within some original JSON text.
     */
    const TextLoc& loc() const noexcept
    {
        return _mLoc;
    }

    /*
     * True if this JSON value is a JSON null value.
     */
    bool isNull() const noexcept
    {
        return _mType == Type::Null;
    }

    /*
     * True if this JSON value is a JSON boolean value.
     */
    bool isBool() const noexcept
    {
        return _mType == Type::Bool;
    }

    /*
     * True if this JSON value is a JSON signed integer value.
     */
    bool isSInt() const noexcept
    {
        return _mType == Type::SInt;
    }

    /*
     * True if this JSON value is a JSON unsigned integer value.
     */
    bool isUInt() const noexcept
    {
        return _mType == Type::UInt;
    }

    /*
     * True if this JSON value is a JSON real value.
     */
    bool isReal() const noexcept
    {
        return _mType == Type::Real;
    }

    /*
     * True if this JSON value is a JSON string value.
     */
    bool isStr() const noexcept
    {
        return _mType == Type::Str;
    }

    /*
     * True if this JSON value is a JSON array value.
     */
    bool isArray() const noexcept
    {
        return _mType == Type::Array;
    }

    /*
     * True if this JSON value is a JSON object value.
     */
    bool isObj() const noexcept
    {
        return _mType == Type::Obj;
    }

    /*
     * Returns this JSON value as a JSON null value.
     */
    const JsonNullVal& asNull() const noexcept;

    /*
     * Returns this JSON value as a JSON boolean value.
     */
    const JsonBoolVal& asBool() const noexcept;

    /*
     * Returns this JSON value as a JSON signed integer value.
     */
    const JsonSIntVal& asSInt() const noexcept;

    /*
     * Returns this JSON value as a JSON unsigned integer value.
     */
    const JsonUIntVal& asUInt() const noexcept;

    /*
     * Returns this JSON value as a JSON real value.
     */
    const JsonRealVal& asReal() const noexcept;

    /*
     * Returns this JSON value as a JSON string value.
     */
    const JsonStrVal& asStr() const noexcept;

    /*
     * Returns this JSON value as a JSON array value.
     */
    const JsonArrayVal& asArray() const noexcept;

    /*
     * Returns this JSON value as a JSON object value.
     */
    const JsonObjVal& asObj() const noexcept;

    /*
     * Accepts the visitor `visitor` to visit this JSON value.
     */
    void accept(JsonValVisitor& visitor) const;

private:
    virtual void _accept(JsonValVisitor& visitor) const = 0;

    /* JSON value type */
    Type _mType;

    /* Location of this value within some original JSON text */
    TextLoc _mLoc;
};

/*
 * JSON null value.
 */
class JsonNullVal : public JsonVal
{
public:
    /* Unique pointer to constant JSON null value */
    using UP = std::unique_ptr<const JsonNullVal>;

    /*
     * Builds a JSON null value located at `loc`.
     */
    explicit JsonNullVal(TextLoc loc) noexcept;

private:
    void _accept(JsonValVisitor& visitor) const override;
};

/*
 * JSON scalar value (template for any class which contains a single
 * scalar value member of type `ValT`).
 */
template <typename ValT, JsonValType TypeV>
class JsonScalarVal : public JsonVal
{
public:
    /* Raw value type */
    using Val = ValT;

    /* Unique pointer to constant JSON scalar value */
    using UP = std::unique_ptr<const JsonScalarVal<ValT, TypeV>>;

    /*
     * Builds a JSON scalar value with the raw value `val` and located
     * at `loc`.
     */
    explicit JsonScalarVal(ValT val, TextLoc loc) noexcept :
        JsonVal {TypeV, std::move(loc)}, _mVal {std::move(val)}
    {
    }

    /*
     * Returns the raw value of this JSON value.
     */
    const ValT& val() const noexcept
    {
        return _mVal;
    }

    /*
     * Returns the raw value of this JSON value.
     */
    const ValT& operator*() const noexcept
    {
        return _mVal;
    }

private:
    void _accept(JsonValVisitor& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    /* Raw value */
    ValT _mVal;
};

/*
 * Abstract base class for any JSON compound value class having
 * `ContainerT` as the type of its JSON value container.
 */
template <typename ContainerT, JsonValType TypeV>
class JsonCompoundVal : public JsonVal
{
public:
    /* JSON value container type */
    using Container = ContainerT;

protected:
    /*
     * Builds a JSON compound value of type `TypeV` and located at
     * `loc`, moving the JSON values `vals` into this.
     */
    explicit JsonCompoundVal(ContainerT&& vals, TextLoc&& loc) :
        JsonVal {TypeV, std::move(loc)}, _mVals {std::move(vals)}
    {
    }

public:
    /*
     * Constant beginning iterator of this JSON compound value.
     */
    typename ContainerT::const_iterator begin() const noexcept
    {
        return _mVals.begin();
    }

    /*
     * Constant past-the-end iterator of this JSON compound value.
     */
    typename ContainerT::const_iterator end() const noexcept
    {
        return _mVals.end();
    }

    /*
     * Size of this JSON compound value.
     */
    std::size_t size() const noexcept
    {
        return _mVals.size();
    }

    /*
     * Whether or not this JSON compound value is empty.
     */
    bool isEmpty() const noexcept
    {
        return _mVals.empty();
    }

protected:
    /* Container of JSON values */
    ContainerT _mVals;
};

/*
 * JSON array value.
 */
class JsonArrayVal : public JsonCompoundVal<std::vector<JsonVal::UP>, JsonValType::Array>
{
public:
    /* Unique pointer to constant JSON array value */
    using UP = std::unique_ptr<const JsonArrayVal>;

    /*
     * Builds a JSON array value located at `loc`, moving the JSON
     * values `vals` into this.
     */
    explicit JsonArrayVal(Container&& vals, TextLoc loc);

    /*
     * Returns the JSON value at index `index` within this JSON array
     * value.
     */
    const JsonVal& operator[](const std::size_t index) const noexcept
    {
        BT_ASSERT_DBG(index < this->_mVals.size());
        return *_mVals[index];
    }

private:
    void _accept(JsonValVisitor& visitor) const override;
};

/*
 * JSON object value.
 */
class JsonObjVal :
    public JsonCompoundVal<std::unordered_map<std::string, JsonVal::UP>, JsonValType::Obj>
{
public:
    /* Unique pointer to constant JSON object value */
    using UP = std::unique_ptr<const JsonObjVal>;

    /*
     * Builds a JSON object value located at `loc`, moving the JSON
     * values `vals` into this.
     */
    explicit JsonObjVal(Container&& vals, TextLoc loc);

    /*
     * Returns the JSON value named `key` within this JSON object
     * value, or `nullptr` if not found.
     */
    const JsonVal *operator[](const std::string& key) const noexcept
    {
        const auto it = _mVals.find(key);

        if (it == _mVals.end()) {
            return nullptr;
        }

        return it->second.get();
    }

    /*
     * Returns the JSON value having the key `key`, known to exist, as
     * a `JsonValT` reference.
     */
    template <typename JsonValT>
    const JsonValT& val(const std::string& key) const noexcept
    {
        const auto val = (*this)[key];

        BT_ASSERT(val);
        return static_cast<const JsonValT&>(*val);
    }

    /*
     * Returns the raw value of the JSON boolean value, known to exist,
     * having the key `key`.
     */
    bool rawBoolVal(const std::string& key) const noexcept
    {
        return *this->val<JsonBoolVal>(key);
    }

    /*
     * Returns the raw value of the JSON unsigned integer value, known
     * to exist, having the key `key`.
     */
    unsigned long long rawUIntVal(const std::string& key) const noexcept
    {
        return *this->val<JsonUIntVal>(key);
    }

    /*
     * Returns the raw value of the JSON signed integer value, known to
     * exist, having the key `key`.
     */
    long long rawSIntVal(const std::string& key) const noexcept
    {
        return *this->val<JsonSIntVal>(key);
    }

    /*
     * Returns the raw value of the JSON real value, known to exist,
     * having the key `key`.
     */
    double rawRealVal(const std::string& key) const noexcept
    {
        return *this->val<JsonRealVal>(key);
    }

    /*
     * Returns the raw value of the JSON string value, known to exist,
     * having the key `key`.
     */
    const std::string& rawStrVal(const std::string& key) const noexcept
    {
        return *this->val<JsonStrVal>(key);
    }

    /*
     * Returns:
     *
     * If a JSON value having the key `key` exists:
     *     The JSON value having the key `key` as a `JsonValT`
     *     reference.
     *
     * Otherwise:
     *     `defJsonVal`
     */
    template <typename JsonValT>
    const JsonValT& val(const std::string& key, const JsonValT& defJsonVal) const noexcept
    {
        const auto jsonVal = (*this)[key];

        return jsonVal ? static_cast<const JsonValT&>(*jsonVal) : defJsonVal;
    }

    /*
     * Returns:
     *
     * If a JSON value having the key `key` exists:
     *     The raw value of the JSON value having the key `key`.
     *
     * Otherwise:
     *     `defVal`
     */
    template <typename JsonValT>
    typename JsonValT::Val rawVal(const std::string& key,
                                  const typename JsonValT::Val defVal) const noexcept
    {
        const auto jsonVal = (*this)[key];

        return jsonVal ? *static_cast<const JsonValT&>(*jsonVal) : defVal;
    }

    /*
     * Returns:
     *
     * If a JSON value having the key `key` exists:
     *     The raw value of the JSON boolean value having the key `key`.
     *
     * Otherwise:
     *     `defVal`
     */
    bool rawVal(const std::string& key, const bool defVal) const noexcept
    {
        return this->rawVal<JsonBoolVal>(key, defVal);
    }

    /*
     * Returns:
     *
     * If a JSON value having the key `key` exists:
     *     The raw value of the JSON unsigned integer value having the
     *     key `key`.
     *
     * Otherwise:
     *     `defVal`
     */
    unsigned long long rawVal(const std::string& key,
                              const unsigned long long defVal) const noexcept
    {
        return this->rawVal<JsonUIntVal>(key, defVal);
    }

    /*
     * Returns:
     *
     * If a JSON value having the key `key` exists:
     *     The raw value of the JSON signed integer value having the key
     *     `key`.
     *
     * Otherwise:
     *     `defVal`
     */
    long long rawVal(const std::string& key, const long long defVal) const noexcept
    {
        return this->rawVal<JsonSIntVal>(key, defVal);
    }

    /*
     * Returns:
     *
     * If a JSON value having the key `key` exists:
     *     The raw value of the JSON real value having the key `key`.
     *
     * Otherwise:
     *     `defVal`
     */
    double rawVal(const std::string& key, const double defVal) const noexcept
    {
        return this->rawVal<JsonRealVal>(key, defVal);
    }

    /*
     * Returns:
     *
     * If a JSON value having the key `key` exists:
     *     The raw value of the JSON string value having the key `key`.
     *
     * Otherwise:
     *     `defVal`
     */
    const char *rawVal(const std::string& key, const char * const defVal) const noexcept
    {
        const auto jsonVal = (*this)[key];

        return jsonVal ? (*jsonVal->asStr()).c_str() : defVal;
    }

    /*
     * Returns whether or not this JSON object value contains a value
     * named `key`.
     */
    bool hasValue(const std::string& key) const noexcept
    {
        return _mVals.find(key) != _mVals.end();
    }

private:
    void _accept(JsonValVisitor& visitor) const override;
};

/*
 * Creates and returns a JSON null value located at `loc`.
 */
JsonNullVal::UP createJsonVal(TextLoc loc);

/*
 * Creates and returns a JSON boolean value having the raw value `val`
 * located at `loc`.
 */
JsonBoolVal::UP createJsonVal(bool val, TextLoc loc);

/*
 * Creates and returns a JSON signed integer value having the raw value
 * `val` located at `loc`.
 */
JsonSIntVal::UP createJsonVal(long long val, TextLoc loc);

/*
 * Creates and returns a JSON unsigned integer value having the raw
 * value `val` located at `loc`.
 */
JsonUIntVal::UP createJsonVal(unsigned long long val, TextLoc loc);

/*
 * Creates and returns a JSON real number value having the raw value
 * `val` located at `loc`.
 */
JsonRealVal::UP createJsonVal(double val, TextLoc loc);

/*
 * Creates and returns a JSON string value having the raw value `val`
 * located at `loc`.
 */
JsonStrVal::UP createJsonVal(std::string val, TextLoc loc);

/*
 * Creates and returns a JSON array value located at `loc`, moving the
 * JSON values `vals`.
 */
JsonArrayVal::UP createJsonVal(JsonArrayVal::Container&& vals, TextLoc loc);

/*
 * Creates and returns a JSON object value located at `loc`, moving the
 * JSON values `vals`.
 */
JsonObjVal::UP createJsonVal(JsonObjVal::Container&& vals, TextLoc loc);

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_JSON_VAL_HPP */
