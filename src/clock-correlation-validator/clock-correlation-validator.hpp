/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2024 EfficiOS, Inc.
 */

#ifndef BABELTRACE_CLOCK_CORRELATION_VALIDATOR_CLOCK_CORRELATION_VALIDATOR_HPP
#define BABELTRACE_CLOCK_CORRELATION_VALIDATOR_CLOCK_CORRELATION_VALIDATOR_HPP

#include "cpp-common/bt2/message.hpp"

#include "clock-correlation-validator/clock-correlation-validator.h"

namespace bt2ccv {

class ClockCorrelationError final : public std::runtime_error
{
public:
    enum class Type
    {
        ExpectingNoClockClassGotOne =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_NO_CLOCK_CLASS_GOT_ONE,

        ExpectingOriginUnixGotNoClockClass =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNIX_GOT_NO_CLOCK_CLASS,
        ExpectingOriginUnixGotUnknownOrigin =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNIX_GOT_UNKNOWN_ORIGIN,

        ExpectingOriginUnknownWithUuidGotNoClockClass =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_UUID_GOT_NO_CLOCK_CLASS,
        ExpectingOriginUnknownWithUuidGotUnixOrigin =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_UUID_GOT_UNIX_ORIGIN,
        ExpectingOriginUnknownWithUuidGotWithoutUuid =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_UUID_GOT_WITHOUT_UUID,
        ExpectingOriginUnknownWithUuidGotOtherUuid =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITH_UUID_GOT_OTHER_UUID,

        ExpectingOriginUnknownWithoutUuidGotNoClockClass =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITHOUT_UUID_GOT_NO_CLOCK_CLASS,
        ExpectingOriginUnknownWithoutUuidGotOtherClockClass =
            BT_CLOCK_CORRELATION_VALIDATOR_ERROR_TYPE_EXPECTING_ORIGIN_UNKNOWN_WITHOUT_UUID_GOT_OTHER_CLOCK_CLASS,
    };

    explicit ClockCorrelationError(
        Type type, const bt2::OptionalBorrowedObject<bt2::ConstClockClass> actualClockCls,
        const bt2::OptionalBorrowedObject<bt2::ConstClockClass> refClockCls,
        const bt2::OptionalBorrowedObject<bt2::ConstStreamClass> streamCls) noexcept :
        std::runtime_error {"Clock classes are not correlatable"},
        _mType {type}, _mActualClockCls {actualClockCls}, _mRefClockCls {refClockCls},
        _mStreamCls {streamCls}

    {
    }

    Type type() const noexcept
    {
        return _mType;
    }

    bt2::OptionalBorrowedObject<bt2::ConstClockClass> actualClockCls() const noexcept
    {
        return _mActualClockCls;
    }

    bt2::OptionalBorrowedObject<bt2::ConstClockClass> refClockCls() const noexcept
    {
        return _mRefClockCls;
    }

    bt2::OptionalBorrowedObject<bt2::ConstStreamClass> streamCls() const noexcept
    {
        return _mStreamCls;
    }

private:
    Type _mType;
    bt2::OptionalBorrowedObject<bt2::ConstClockClass> _mActualClockCls;
    bt2::OptionalBorrowedObject<bt2::ConstClockClass> _mRefClockCls;
    bt2::OptionalBorrowedObject<bt2::ConstStreamClass> _mStreamCls;
};

class ClockCorrelationValidator final
{
private:
    enum class PropsExpectation
    {
        /* We haven't recorded clock properties yet. */
        Unset,

        /* Expect to have no clock. */
        None,

        /* Expect a clock with a Unix epoch origin. */
        OriginUnix,

        /* Expect a clock with an unknown origin, but with a UUID. */
        OriginUnknownWithUuid,

        /* Expect a clock with an unknown origin and without a UUID. */
        OriginUnknownWithoutUuid,
    };

public:
    void validate(const bt2::ConstMessage msg)
    {
        if (!msg.isStreamBeginning() && !msg.isMessageIteratorInactivity()) {
            return;
        }

        this->_validate(msg);
    }

private:
    void _validate(const bt2::ConstMessage msg);

    PropsExpectation _mExpectation = PropsExpectation::Unset;

    /*
     * Reference clock class: the clock class used to set expectations.
     *
     * To make sure that the clock class pointed to by this member
     * doesn't get freed and another one reallocated at the same
     * address, keep a strong reference, ensuring that it lives at least
     * as long as the owner of this validator.
     */
    bt2::ConstClockClass::Shared _mRefClockClass;
};

} /* namespace bt2ccv */

#endif /* BABELTRACE_CLOCK_CORRELATION_VALIDATOR_CLOCK_CORRELATION_VALIDATOR_HPP */
