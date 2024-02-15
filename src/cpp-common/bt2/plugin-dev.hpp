/*
 * Copyright (c) 2023 Simon Marchi <simon.marchi@efficios.com>
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2_PLUGIN_DEV_HPP
#define BABELTRACE_CPP_COMMON_BT2_PLUGIN_DEV_HPP

#include <cstdint>

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/c-string-view.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/vendor/fmt/core.h"

#include "exc.hpp"
#include "internal/comp-cls-bridge.hpp" /* IWYU pragma: keep */

namespace bt2 {

template <typename UserMessageIteratorT, typename UserComponentT>
class UserMessageIterator;

/*
 * Base class of any user component.
 *
 * See the specific `bt2::UserSourceComponent`,
 * `bt2::UserFilterComponent`, and `bt2::UserSinkComponent`.
 */
template <typename SelfCompT, typename InitDataT, typename QueryDataT>
class UserComponent
{
    /* Give a related message iterator access to this logger */
    template <typename, typename>
    friend class UserMessageIterator;

public:
    using InitData = InitDataT;
    using QueryData = QueryDataT;

protected:
    explicit UserComponent(const SelfCompT selfComp, const std::string& logTag) :
        _mLogger {selfComp, fmt::format("{}/[{}]", logTag, selfComp.name())}, _mSelfComp {selfComp}
    {
    }

protected:
    bt2c::CStringView _name() const noexcept
    {
        return _mSelfComp.name();
    }

    LoggingLevel _loggingLevel() const noexcept
    {
        return _mSelfComp.loggingLevel();
    }

    std::uint64_t _graphMipVersion() const noexcept
    {
        return _mSelfComp.graphMipVersion();
    }

    SelfCompT _selfComp() noexcept
    {
        return _mSelfComp;
    }

    bt2c::Logger _mLogger;

private:
    SelfCompT _mSelfComp;
};

/*
 * Base class of a user source component `UserComponentT` (CRTP).
 *
 * UserComponentT::UserComponentT() must accept, in this order:
 *
 *  1. A `bt2::SelfSourceComponent` parameter, which it needs to forward
 *     to bt2::UserSourceComponent::UserSourceComponent().
 *
 *  2. A `bt2::ConstValue` parameter (the initialization parameters).
 *
 *  3. An `InitDataT *` parameter (the initialization method data).
 *
 * `UserMessageIteratorT`, the message iterator class to use, must inherit
 * `UserMessageIterator`.
 *
 * UserComponentT::_query() receives a query method data pointer of type
 * `QueryDataT *` as its last parameter.
 */
template <typename UserComponentT, typename UserMessageIteratorT, typename InitDataT = void,
          typename QueryDataT = void>
class UserSourceComponent : public UserComponent<SelfSourceComponent, InitDataT, QueryDataT>
{
    static_assert(std::is_base_of<UserMessageIterator<UserMessageIteratorT, UserComponentT>,
                                  UserMessageIteratorT>::value,
                  "`UserMessageIteratorT` inherits `UserMessageIterator`");

public:
    using MessageIterator = UserMessageIteratorT;

protected:
    using _OutputPorts = SelfSourceComponent::OutputPorts;

    explicit UserSourceComponent(const SelfSourceComponent selfComp, const std::string& logTag) :
        UserComponent<SelfSourceComponent, InitDataT, QueryDataT> {selfComp, logTag}
    {
    }

public:
    static Value::Shared query(const SelfComponentClass selfCompCls,
                               const PrivateQueryExecutor privQueryExec,
                               const bt2c::CStringView obj, const ConstValue params,
                               QueryDataT * const data)
    {
        return UserComponentT::_query(selfCompCls, privQueryExec, obj, params, data);
    }

    static void getSupportedMipVersions(const SelfComponentClass selfCompCls,
                                        const ConstValue params, const LoggingLevel loggingLevel,
                                        const UnsignedIntegerRangeSet ranges)
    {
        UserComponentT::_getSupportedMipVersions(selfCompCls, params, loggingLevel, ranges);
    }

    void outputPortConnected(const SelfComponentOutputPort outputPort,
                             const ConstInputPort inputPort)
    {
        static_cast<UserComponentT&>(*this)._outputPortConnected(outputPort, inputPort);
    }

protected:
    /* Overloadable */
    static Value::Shared _query(SelfComponentClass, PrivateQueryExecutor, bt2c::CStringView,
                                ConstValue, QueryDataT *)
    {
        throw UnknownObject {};
    }

    /* Overloadable */
    static void _getSupportedMipVersions(SelfComponentClass, ConstValue, LoggingLevel,
                                         const UnsignedIntegerRangeSet ranges)
    {
        ranges.addRange(0, 0);
    }

    /* Overloadable */
    void _outputPortConnected(SelfComponentOutputPort, ConstInputPort)
    {
    }

    template <typename DataT>
    _OutputPorts::Port _addOutputPort(const bt2c::CStringView name, DataT& data)
    {
        return this->_selfComp().addOutputPort(name, data);
    }

    _OutputPorts::Port _addOutputPort(const bt2c::CStringView name)
    {
        return this->_selfComp().addOutputPort(name);
    }

    _OutputPorts _outputPorts() noexcept
    {
        return this->_selfComp().outputPorts();
    }
};

/*
 * Base class of a user filter component `UserComponentT` (CRTP).
 *
 * UserComponentT::UserComponentT() must accept, in this order:
 *
 *  1. A `bt2::SelfFilterComponent` parameter, which it needs to forward
 *     to bt2::UserFilterComponent::UserFilterComponent().
 *
 *  2. A `bt2::ConstValue` parameter (the initialization parameters).
 *
 *  3. An `InitDataT *` parameter (the initialization method data).
 *
 * `UserMessageIteratorT`, the message iterator class to use, must inherit
 * `UserMessageIterator`.
 *
 * UserComponentT::_query() receives a query method data pointer of type
 * `QueryDataT *` as its last parameter.
 */
template <typename UserComponentT, typename UserMessageIteratorT, typename InitDataT = void,
          typename QueryDataT = void>
class UserFilterComponent : public UserComponent<SelfFilterComponent, InitDataT, QueryDataT>
{
    static_assert(std::is_base_of<UserMessageIterator<UserMessageIteratorT, UserComponentT>,
                                  UserMessageIteratorT>::value,
                  "`UserMessageIteratorT` inherits `UserMessageIterator`");

public:
    using MessageIterator = UserMessageIteratorT;

protected:
    using _InputPorts = SelfFilterComponent::InputPorts;
    using _OutputPorts = SelfFilterComponent::OutputPorts;

    explicit UserFilterComponent(const SelfFilterComponent selfComp, const std::string& logTag) :
        UserComponent<SelfFilterComponent, InitDataT, QueryDataT> {selfComp, logTag}
    {
    }

public:
    static Value::Shared query(const SelfComponentClass selfCompCls,
                               const PrivateQueryExecutor privQueryExec,
                               const bt2c::CStringView obj, const ConstValue params,
                               QueryDataT * const data)
    {
        return UserComponentT::_query(selfCompCls, privQueryExec, obj, params, data);
    }

    static void getSupportedMipVersions(const SelfComponentClass selfCompCls,
                                        const ConstValue params, const LoggingLevel loggingLevel,
                                        const UnsignedIntegerRangeSet ranges)
    {
        UserComponentT::_getSupportedMipVersions(selfCompCls, params, loggingLevel, ranges);
    }

    void inputPortConnected(const SelfComponentInputPort inputPort,
                            const ConstOutputPort outputPort)
    {
        static_cast<UserComponentT&>(*this)._inputPortConnected(inputPort, outputPort);
    }

    void outputPortConnected(const SelfComponentOutputPort outputPort,
                             const ConstInputPort inputPort)
    {
        static_cast<UserComponentT&>(*this)._outputPortConnected(outputPort, inputPort);
    }

protected:
    /* Overloadable */
    static Value::Shared _query(SelfComponentClass, PrivateQueryExecutor, bt2c::CStringView,
                                ConstValue, QueryDataT *)
    {
        throw UnknownObject {};
    }

    /* Overloadable */
    static void _getSupportedMipVersions(SelfComponentClass, ConstValue, LoggingLevel,
                                         const UnsignedIntegerRangeSet ranges)
    {
        ranges.addRange(0, 0);
    }

    /* Overloadable */
    void _inputPortConnected(SelfComponentInputPort, ConstOutputPort)
    {
    }

    /* Overloadable */
    void _outputPortConnected(SelfComponentOutputPort, ConstInputPort)
    {
    }

    template <typename DataT>
    _OutputPorts::Port _addInputPort(const bt2c::CStringView name, DataT& data)
    {
        return this->_selfComp().addInputPort(name, data);
    }

    _InputPorts::Port _addInputPort(const bt2c::CStringView name)
    {
        return this->_selfComp().addInputPort(name);
    }

    _InputPorts _inputPorts() noexcept
    {
        return this->_selfComp().inputPorts();
    }

    template <typename DataT>
    _OutputPorts::Port _addOutputPort(const bt2c::CStringView name, DataT& data)
    {
        return this->_selfComp().addOutputPort(name, data);
    }

    _OutputPorts::Port _addOutputPort(const bt2c::CStringView name)
    {
        return this->_selfComp().addOutputPort(name);
    }

    _OutputPorts _outputPorts() noexcept
    {
        return this->_selfComp().outputPorts();
    }
};

/*
 * Base class of a user sink component `UserComponentT` (CRTP).
 *
 * UserComponentT::UserComponentT() must accept, in this order:
 *
 *  1. A `bt2::SelfSinkComponent` parameter, which it needs to forward
 *     to bt2::UserSinkComponent::UserSinkComponent().
 *
 *  2. A `bt2::ConstValue` parameter (the initialization parameters).
 *
 *  3. An `InitDataT *` parameter (the initialization method data).
 *
 * `UserComponentT` must implement:
 *
 *     bool _consume();
 *
 * This method returns `true` if the sink component still needs to
 * consume, or `false` if it's finished.
 *
 * UserComponentT::_query() receives a query method data pointer of type
 * `QueryDataT *` as its last parameter.

 */
template <typename UserComponentT, typename InitDataT = void, typename QueryDataT = void>
class UserSinkComponent : public UserComponent<SelfSinkComponent, InitDataT, QueryDataT>
{
protected:
    using _InputPorts = SelfSinkComponent::InputPorts;

    explicit UserSinkComponent(const SelfSinkComponent selfComp, const std::string& logTag) :
        UserComponent<SelfSinkComponent, InitDataT, QueryDataT> {selfComp, logTag}
    {
    }

public:
    static Value::Shared query(const SelfComponentClass selfCompCls,
                               const PrivateQueryExecutor privQueryExec,
                               const bt2c::CStringView obj, const ConstValue params,
                               QueryDataT * const data)
    {
        return UserComponentT::_query(selfCompCls, privQueryExec, obj, params, data);
    }

    static void getSupportedMipVersions(const SelfComponentClass selfCompCls,
                                        const ConstValue params, const LoggingLevel loggingLevel,
                                        const UnsignedIntegerRangeSet ranges)
    {
        UserComponentT::_getSupportedMipVersions(selfCompCls, params, loggingLevel, ranges);
    }

    void graphIsConfigured()
    {
        static_cast<UserComponentT&>(*this)._graphIsConfigured();
    }

    void inputPortConnected(const SelfComponentInputPort inputPort,
                            const ConstOutputPort outputPort)
    {
        static_cast<UserComponentT&>(*this)._inputPortConnected(inputPort, outputPort);
    }

    bool consume()
    {
        return static_cast<UserComponentT&>(*this)._consume();
    }

protected:
    /* Overloadable */
    static Value::Shared _query(SelfComponentClass, PrivateQueryExecutor, bt2c::CStringView,
                                ConstValue, QueryDataT *)
    {
        throw UnknownObject {};
    }

    /* Overloadable */
    static void _getSupportedMipVersions(SelfComponentClass, ConstValue, LoggingLevel,
                                         const UnsignedIntegerRangeSet ranges)
    {
        ranges.addRange(0, 0);
    }

    /* Overloadable */
    void _graphIsConfigured()
    {
    }

    /* Overloadable */
    void _inputPortConnected(SelfComponentInputPort, ConstOutputPort)
    {
    }

    MessageIterator::Shared _createMessageIterator(const _InputPorts::Port port)
    {
        return this->_selfComp().createMessageIterator(port);
    }

    template <typename DataT>
    _InputPorts::Port _addInputPort(const bt2c::CStringView name, DataT& data)
    {
        return this->_selfComp().addInputPort(name, data);
    }

    _InputPorts::Port _addInputPort(const bt2c::CStringView name)
    {
        return this->_selfComp().addInputPort(name);
    }

    _InputPorts _inputPorts() noexcept
    {
        return this->_selfComp().inputPorts();
    }
};

/*
 * Base class of a user message iterator `UserMessageIteratorT` (CRTP)
 * of which the parent user component class is `UserComponentT`.
 *
 * `UserMessageIteratorT::UserMessageIteratorT()` must accept a
 * `bt2::SelfMessageIterator` parameter, which it needs to forward to
 * bt2::UserMessageIterator::UserMessageIterator().
 *
 * The public next() method below (called by the bridge) implements the
 * very common pattern of appending messages into the output array, and,
 * meanwhile:
 *
 * If it catches a `bt2::TryAgain` exception:
 *     If the message array isn't empty, transform this into a success
 *     (don't throw).
 *
 *     Otherwise rethrow.
 *
 * If it catches an error:
 *     If the message array isn't empty, transform this into a success
 *     (don't throw), but save the error of the current thread and the
 *     type of error to throw the next time the user calls next().
 *
 *     Otherwise rethrow.
 *
 * `UserMessageIteratorT` must implement:
 *
 *     void _next(bt2::ConstMessageArray& messages);
 *
 * This method fills `messages` with at most `messages.capacity()`
 * messages and may throw `bt2::TryAgain` or a valid error whenever.
 * Leaving an empty `messages` means the end of iteration.
 */
template <typename UserMessageIteratorT, typename UserComponentT>
class UserMessageIterator
{
private:
    /* Type of `_mExcToThrowType` */
    enum class _ExcToThrowType
    {
        NONE,
        ERROR,
        MEM_ERROR,
    };

protected:
    explicit UserMessageIterator(const SelfMessageIterator selfMsgIter,
                                 const std::string& logTagSuffix) :
        _mSelfMsgIter {selfMsgIter},
        _mLogger {selfMsgIter,
                  fmt::format("{}/{}", this->_component()._mLogger.tag(), logTagSuffix)}
    {
    }

public:
    ~UserMessageIterator()
    {
        this->_resetError();
    }

    void next(bt2::ConstMessageArray& messages)
    {
        /* Any saved error? Now is the time to throw */
        if (G_UNLIKELY(_mExcToThrowType != _ExcToThrowType::NONE)) {
            /* Move `_mSavedLibError`, if any, as current thread error */
            if (_mSavedLibError) {
                BT_CURRENT_THREAD_MOVE_ERROR_AND_RESET(_mSavedLibError);
            }

            /* Throw the corresponding exception */
            if (_mExcToThrowType == _ExcToThrowType::ERROR) {
                throw bt2::Error {};
            } else {
                BT_ASSERT(_mExcToThrowType == _ExcToThrowType::MEM_ERROR);
                throw bt2::MemoryError {};
            }
        }

        /*
         * When catching some exception below, if our message array
         * isn't empty, then return immediately before throwing to
         * provide those messages to downstream.
         *
         * When catching an error, also save the current thread error,
         * if any, so that we can restore it later (see the beginning of
         * this method).
         */
        BT_ASSERT_DBG(_mExcToThrowType == _ExcToThrowType::NONE);

        try {
            this->_userObj()._next(messages);

            /* We're done: everything below is exception handling */
            return;
        } catch (const bt2::TryAgain&) {
            if (messages.isEmpty()) {
                throw;
            }
        } catch (const std::bad_alloc&) {
            if (messages.isEmpty()) {
                throw;
            }

            _mExcToThrowType = _ExcToThrowType::MEM_ERROR;
        } catch (const bt2::Error&) {
            if (messages.isEmpty()) {
                throw;
            }

            _mExcToThrowType = _ExcToThrowType::ERROR;
        }

        if (_mExcToThrowType != _ExcToThrowType::NONE) {
            BT_CPPLOGE(
                "An error occurred, but there are {} messages to return: delaying the error reporting.",
                messages.length());
            BT_ASSERT(!_mSavedLibError);
            _mSavedLibError = bt_current_thread_take_error();
        }
    }

    bool canSeekBeginning()
    {
        this->_resetError();
        return this->_userObj()._canSeekBeginning();
    }

    void seekBeginning()
    {
        this->_resetError();
        return this->_userObj()._seekBeginning();
    }

    bool canSeekNsFromOrigin(const std::int64_t nsFromOrigin)
    {
        this->_resetError();
        return this->_userObj()._canSeekNsFromOrigin(nsFromOrigin);
    }

    void seekNsFromOrigin(const std::int64_t nsFromOrigin)
    {
        this->_resetError();
        this->_userObj()._seekNsFromOrigin(nsFromOrigin);
    }

protected:
    /* Overloadable */
    bool _canSeekBeginning() noexcept
    {
        return false;
    }

    /* Overloadable */
    void _seekBeginning() noexcept
    {
    }

    /* Overloadable */
    bool _canSeekNsFromOrigin(std::int64_t) noexcept
    {
        return false;
    }

    /* Overloadable */
    void _seekNsFromOrigin(std::int64_t) noexcept
    {
    }

    MessageIterator::Shared _createMessageIterator(const SelfComponentInputPort port)
    {
        return _mSelfMsgIter.createMessageIterator(port);
    }

    UserComponentT& _component() noexcept
    {
        return _mSelfMsgIter.component().template data<UserComponentT>();
    }

    SelfComponentOutputPort _port() noexcept
    {
        return _mSelfMsgIter.port();
    }

    bool _isInterrupted() const noexcept
    {
        return _mSelfMsgIter.isInterrupted();
    }

private:
    UserMessageIteratorT& _userObj() noexcept
    {
        return static_cast<UserMessageIteratorT&>(*this);
    }

    void _resetError() noexcept
    {
        _mExcToThrowType = _ExcToThrowType::NONE;

        if (_mSavedLibError) {
            bt_error_release(_mSavedLibError);
        }
    }

    SelfMessageIterator _mSelfMsgIter;

    /*
     * next() may accumulate messages, and then catch an error before
     * returning. In that case, it saves the error of the current thread
     * here so that it can return its accumulated messages and throw the
     * next time.
     *
     * It also saves the type of the exception to throw the next time.
     */
    _ExcToThrowType _mExcToThrowType = _ExcToThrowType::NONE;
    const bt_error *_mSavedLibError = nullptr;

protected:
    bt2c::Logger _mLogger;
};

} /* namespace bt2 */

#define BT_CPP_PLUGIN_SOURCE_COMPONENT_CLASS_WITH_ID(_pluginId, _componentClassId, _name,          \
                                                     _userComponentClass)                          \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_WITH_ID(                                                      \
        _pluginId, _componentClassId, _name,                                                       \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::next);              \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_INITIALIZE_METHOD_WITH_ID(                                    \
        _pluginId, _componentClassId, bt2::internal::SrcCompClsBridge<_userComponentClass>::init); \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_FINALIZE_METHOD_WITH_ID(                                      \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SrcCompClsBridge<_userComponentClass>::finalize);                           \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_WITH_ID(                    \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SrcCompClsBridge<_userComponentClass>::getSupportedMipVersions);            \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_OUTPUT_PORT_CONNECTED_METHOD_WITH_ID(                         \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SrcCompClsBridge<_userComponentClass>::outputPortConnected);                \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_QUERY_METHOD_WITH_ID(                                         \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SrcCompClsBridge<_userComponentClass>::query);                              \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_WITH_ID(             \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::init);              \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_FINALIZE_METHOD_WITH_ID(               \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::finalize);          \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHODS_WITH_ID(        \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::seekBeginning,      \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::canSeekBeginning);  \
    BT_PLUGIN_SOURCE_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_SEEK_NS_FROM_ORIGIN_METHODS_WITH_ID(   \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::seekNsFromOrigin,   \
        bt2::internal::MsgIterClsBridge<                                                           \
            _userComponentClass::MessageIterator>::canSeekNsFromOrigin);

#define BT_CPP_PLUGIN_FILTER_COMPONENT_CLASS_WITH_ID(_pluginId, _componentClassId, _name,          \
                                                     _userComponentClass)                          \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_WITH_ID(                                                      \
        _pluginId, _componentClassId, _name,                                                       \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::next);              \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_INITIALIZE_METHOD_WITH_ID(                                    \
        _pluginId, _componentClassId, bt2::internal::FltCompClsBridge<_userComponentClass>::init); \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_FINALIZE_METHOD_WITH_ID(                                      \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::FltCompClsBridge<_userComponentClass>::finalize);                           \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_WITH_ID(                    \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::FltCompClsBridge<_userComponentClass>::getSupportedMipVersions);            \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_INPUT_PORT_CONNECTED_METHOD_WITH_ID(                          \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::FltCompClsBridge<_userComponentClass>::inputPortConnected);                 \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_OUTPUT_PORT_CONNECTED_METHOD_WITH_ID(                         \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::FltCompClsBridge<_userComponentClass>::outputPortConnected);                \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_QUERY_METHOD_WITH_ID(                                         \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::FltCompClsBridge<_userComponentClass>::query);                              \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_WITH_ID(             \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::init);              \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_FINALIZE_METHOD_WITH_ID(               \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::finalize);          \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHODS_WITH_ID(        \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::seekBeginning,      \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::canSeekBeginning);  \
    BT_PLUGIN_FILTER_COMPONENT_CLASS_MESSAGE_ITERATOR_CLASS_SEEK_NS_FROM_ORIGIN_METHODS_WITH_ID(   \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::MsgIterClsBridge<_userComponentClass::MessageIterator>::seekNsFromOrigin,   \
        bt2::internal::MsgIterClsBridge<                                                           \
            _userComponentClass::MessageIterator>::canSeekNsFromOrigin);

#define BT_CPP_PLUGIN_SINK_COMPONENT_CLASS_WITH_ID(_pluginId, _componentClassId, _name,            \
                                                   _userComponentClass)                            \
    BT_PLUGIN_SINK_COMPONENT_CLASS_WITH_ID(                                                        \
        _pluginId, _componentClassId, _name,                                                       \
        bt2::internal::SinkCompClsBridge<_userComponentClass>::consume);                           \
    BT_PLUGIN_SINK_COMPONENT_CLASS_INITIALIZE_METHOD_WITH_ID(                                      \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SinkCompClsBridge<_userComponentClass>::init);                              \
    BT_PLUGIN_SINK_COMPONENT_CLASS_FINALIZE_METHOD_WITH_ID(                                        \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SinkCompClsBridge<_userComponentClass>::finalize);                          \
    BT_PLUGIN_SINK_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_WITH_ID(                      \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SinkCompClsBridge<_userComponentClass>::getSupportedMipVersions);           \
    BT_PLUGIN_SINK_COMPONENT_CLASS_INPUT_PORT_CONNECTED_METHOD_WITH_ID(                            \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SinkCompClsBridge<_userComponentClass>::inputPortConnected);                \
    BT_PLUGIN_SINK_COMPONENT_CLASS_GRAPH_IS_CONFIGURED_METHOD_WITH_ID(                             \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SinkCompClsBridge<_userComponentClass>::graphIsConfigured);                 \
    BT_PLUGIN_SINK_COMPONENT_CLASS_QUERY_METHOD_WITH_ID(                                           \
        _pluginId, _componentClassId,                                                              \
        bt2::internal::SinkCompClsBridge<_userComponentClass>::query);

#define BT_CPP_PLUGIN_SOURCE_COMPONENT_CLASS(_name, _userComponentClass)                           \
    BT_CPP_PLUGIN_SOURCE_COMPONENT_CLASS_WITH_ID(auto, _name, #_name, _userComponentClass)

#define BT_CPP_PLUGIN_FILTER_COMPONENT_CLASS(_name, _userComponentClass)                           \
    BT_CPP_PLUGIN_FILTER_COMPONENT_CLASS_WITH_ID(auto, _name, #_name, _userComponentClass)

#define BT_CPP_PLUGIN_SINK_COMPONENT_CLASS(_name, _userComponentClass)                             \
    BT_CPP_PLUGIN_SINK_COMPONENT_CLASS_WITH_ID(auto, _name, #_name, _userComponentClass)

#endif /* BABELTRACE_CPP_COMMON_BT2_PLUGIN_DEV_HPP */
