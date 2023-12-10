/*
 * Copyright (c) 2016-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/assert.h"
#include "common/common.h"

#include "parse-json-as-val.hpp"
#include "parse-json.hpp"

namespace bt2c {
namespace {

/*
 * Listener for the listener version of parseJson() which iteratively
 * builds a "root" JSON value.
 */
class JsonValBuilder final
{
public:
    explicit JsonValBuilder(const std::size_t baseOffset) : _mBaseOffset {baseOffset}
    {
    }

    void onNull(const TextLoc& loc)
    {
        this->_handleVal(loc);
    }

    template <typename ValT>
    void onScalarVal(const ValT& val, const TextLoc& loc)
    {
        this->_handleVal(loc, val);
    }

    void onScalarVal(const bt2s::string_view val, const TextLoc& loc)
    {
        this->_handleVal(loc, val.to_string());
    }

    void onArrayBegin(const TextLoc&)
    {
        _mStack.emplace_back(_State::InArray);
    }

    void onArrayEnd(const TextLoc& loc)
    {
        auto arrayValCont = std::move(this->_stackTop().arrayValCont);

        _mStack.pop_back();
        this->_handleVal(loc, std::move(arrayValCont));
    }

    void onObjBegin(const TextLoc&)
    {
        _mStack.emplace_back(_State::InObj);
    }

    void onObjKey(const bt2s::string_view key, const TextLoc&)
    {
        this->_stackTop().lastObjKey = key.to_string();
    }

    void onObjEnd(const TextLoc& loc)
    {
        auto objValCont = std::move(this->_stackTop().objValCont);

        _mStack.pop_back();
        this->_handleVal(loc, std::move(objValCont));
    }

    JsonVal::UP releaseVal() noexcept
    {
        return std::move(_mJsonVal);
    }

private:
    /* The state of a stack frame */
    enum class _State
    {
        InArray,
        InObj,
    };

    /*
     * An entry of `_mStack`.
     */
    struct _StackFrame final
    {
        explicit _StackFrame(const _State stateParam) : state {stateParam}
        {
        }

        _State state;
        JsonArrayVal::Container arrayValCont;
        JsonObjVal::Container objValCont;
        std::string lastObjKey;
    };

private:
    /*
     * Top frame of the stack.
     */
    _StackFrame& _stackTop() noexcept
    {
        BT_ASSERT_DBG(!_mStack.empty());
        return _mStack.back();
    }

    template <typename... ArgTs>
    void _handleVal(const TextLoc& loc, ArgTs&&...args)
    {
        /* Create a JSON value from custom arguments and `loc` */
        auto jsonVal =
            createJsonVal(std::forward<ArgTs>(args)...,
                          TextLoc {loc.offset() + _mBaseOffset, loc.lineNo(), loc.colNo()});

        if (_mStack.empty()) {
            /* Assign as root */
            _mJsonVal = std::move(jsonVal);
            return;
        }

        switch (_mStack.back().state) {
        case _State::InArray:
            /* Append to current JSON array value container */
            this->_stackTop().arrayValCont.push_back(std::move(jsonVal));
            break;

        case _State::InObj:
            /*
             * Insert into current JSON object value container
             *
             * It's safe to move `this->_stackTop().lastObjKey` as it's
             * only used once.
             */
            this->_stackTop().objValCont.insert(
                std::make_pair(std::move(this->_stackTop().lastObjKey), std::move(jsonVal)));
            break;

        default:
            bt_common_abort();
        }
    }

private:
    std::size_t _mBaseOffset;
    std::vector<_StackFrame> _mStack;
    JsonVal::UP _mJsonVal;
};

} /* namespace */

JsonVal::UP parseJson(const bt2s::string_view str, const std::size_t baseOffset,
                      const Logger& logger)
{
    JsonValBuilder builder {baseOffset};

    parseJson(str, builder, baseOffset, logger);
    return builder.releaseVal();
}

} /* namespace bt2c */
