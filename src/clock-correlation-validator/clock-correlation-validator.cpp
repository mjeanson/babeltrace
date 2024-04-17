/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2024 EfficiOS, Inc.
 */

#include "cpp-common/bt2/clock-class.hpp"
#include "cpp-common/bt2/message.hpp"
#include "cpp-common/bt2/wrap.hpp"

#include "clock-correlation-validator.h"
#include "clock-correlation-validator.hpp"

namespace bt2ccv {

void ClockCorrelationValidator::_validate(const bt2::ConstMessage msg)
{
    bt2::OptionalBorrowedObject<bt2::ConstClockClass> clockCls;
    bt2::OptionalBorrowedObject<bt2::ConstStreamClass> streamCls;

    switch (msg.type()) {
    case bt2::MessageType::StreamBeginning:
        streamCls = msg.asStreamBeginning().stream().cls();
        clockCls = streamCls->defaultClockClass();
        break;

    case bt2::MessageType::MessageIteratorInactivity:
        clockCls = msg.asMessageIteratorInactivity().clockSnapshot().clockClass();
        break;

    default:
        bt_common_abort();
    }

    switch (_mExpectation) {
    case PropsExpectation::Unset:
        /*
         * This is the first analysis of a message with a clock
         * snapshot: record the properties of that clock, against which
         * we'll compare the clock properties of the following messages.
         */
        if (!clockCls) {
            _mExpectation = PropsExpectation::None;
        } else if (clockCls->origin().isUnixEpoch()) {
            _mExpectation = PropsExpectation::OriginUnix;
        } else if (const auto uuid = clockCls->uuid()) {
            _mExpectation = PropsExpectation::OriginOtherUuid;
            _mUuid = *uuid;
        } else {
            _mExpectation = PropsExpectation::OriginOtherNoUuid;
            _mClockClass = clockCls->shared();
        }

        break;

    case PropsExpectation::None:
        if (clockCls) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingNoClockClassGotOne,
                                         bt2s::nullopt,
                                         *clockCls,
                                         {},
                                         streamCls};
        }

        break;

    case PropsExpectation::OriginUnix:
        if (!clockCls) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingOriginUnixGotNone,
                                         bt2s::nullopt,
                                         {},
                                         {},
                                         streamCls};
        }

        if (!clockCls->origin().isUnixEpoch()) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingOriginUnixGotOther,
                                         bt2s::nullopt,
                                         *clockCls,
                                         {},
                                         streamCls};
        }

        break;

    case PropsExpectation::OriginOtherUuid:
    {
        if (!clockCls) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingOriginUuidGotNone,
                                         bt2s::nullopt,
                                         {},
                                         {},
                                         streamCls};
        }

        if (clockCls->origin().isUnixEpoch()) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingOriginUuidGotUnix,
                                         bt2s::nullopt,
                                         *clockCls,
                                         {},
                                         streamCls};
        }

        const auto uuid = clockCls->uuid();

        if (!uuid) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingOriginUuidGotNoUuid,
                                         bt2s::nullopt,
                                         *clockCls,
                                         {},
                                         streamCls};
        }

        if (*uuid != _mUuid) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginUuidGotOtherUuid,
                _mUuid,
                *clockCls,
                {},
                streamCls};
        }

        break;
    }

    case PropsExpectation::OriginOtherNoUuid:
        if (!clockCls) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingOriginNoUuidGotNone,
                                         bt2s::nullopt,
                                         {},
                                         {},
                                         streamCls};
        }

        if (clockCls->libObjPtr() != _mClockClass->libObjPtr()) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingOriginNoUuidGotOther,
                                         bt2s::nullopt, *clockCls, *_mClockClass, streamCls};
        }

        break;

    default:
        bt_common_abort();
    }
}

} /* namespace bt2ccv */

bt_clock_correlation_validator *bt_clock_correlation_validator_create() noexcept
{
    try {
        return reinterpret_cast<bt_clock_correlation_validator *>(
            new bt2ccv::ClockCorrelationValidator);
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}

bool bt_clock_correlation_validator_validate_message(
    bt_clock_correlation_validator * const validator, const bt_message * const msg,
    bt_clock_correlation_validator_error_type * const type, bt_uuid * const expectedUuidOut,
    const bt_clock_class ** const actualClockClsOut,
    const bt_clock_class ** const expectedClockClsOut) noexcept
{
    try {
        reinterpret_cast<bt2ccv::ClockCorrelationValidator *>(validator)->validate(bt2::wrap(msg));
        return true;
    } catch (const bt2ccv::ClockCorrelationError& error) {
        *type = static_cast<bt_clock_correlation_validator_error_type>(error.type());

        if (error.expectedUuid()) {
            *expectedUuidOut = error.expectedUuid()->data();
        } else {
            *expectedUuidOut = nullptr;
        }

        if (error.actualClockCls()) {
            *actualClockClsOut = error.actualClockCls()->libObjPtr();
        } else {
            *actualClockClsOut = nullptr;
        }

        if (error.expectedClockCls()) {
            *expectedClockClsOut = error.expectedClockCls()->libObjPtr();
        } else {
            *expectedClockClsOut = nullptr;
        }

        return false;
    }
}

void bt_clock_correlation_validator_destroy(
    bt_clock_correlation_validator * const validator) noexcept
{
    delete reinterpret_cast<bt2ccv::ClockCorrelationValidator *>(validator);
}
