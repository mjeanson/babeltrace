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

namespace {

bool clockClassHasKnownAndComparableIdentity(const bt2::ConstClockClass clockCls,
                                             const std::uint64_t graphMipVersion) noexcept
{
    if (graphMipVersion == 0) {
        return static_cast<bool>(clockCls.uuid());
    } else {
        return clockCls.name() && clockCls.uid();
    }
}

bool clockClassHasKnownAndComparableOrigin(const bt2::ConstClockClass clockCls,
                                           const std::uint64_t graphMipVersion) noexcept
{
    if (graphMipVersion == 0) {
        return clockCls.origin().isUnixEpoch();
    } else {
        return clockCls.origin().isKnown();
    }
}

} /* namespace */

void ClockCorrelationValidator::_validate(const bt2::ConstMessage msg,
                                          const std::uint64_t graphMipVersion)
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
         * snapshot: record the clock class against which we'll compare
         * the clock class properties of the following messages.
         */
        if (clockCls) {
            _mRefClockClass = clockCls->shared();

            if (clockClassHasKnownAndComparableOrigin(*clockCls, graphMipVersion)) {
                _mExpectation = PropsExpectation::OriginKnown;
            } else {
                if (clockClassHasKnownAndComparableIdentity(*clockCls, graphMipVersion)) {
                    _mExpectation = PropsExpectation::OriginUnknownWithId;
                } else {
                    _mExpectation = PropsExpectation::OriginUnknownWithoutId;
                }
            }
        } else {
            _mExpectation = PropsExpectation::None;
        }
        break;

    case PropsExpectation::None:
        if (clockCls) {
            throw ClockCorrelationError {ClockCorrelationError::Type::ExpectingNoClockClassGotOne,
                                         *clockCls,
                                         {},
                                         streamCls};
        }

        break;

    case PropsExpectation::OriginKnown:
        if (!clockCls) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginKnownGotNoClockClass,
                {},
                *_mRefClockClass,
                streamCls};
        }

        if (!clockClassHasKnownAndComparableOrigin(*clockCls, graphMipVersion)) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginKnownGotUnknownOrigin, *clockCls,
                *_mRefClockClass, streamCls};
        }

        /*
         * Under MIP 0, the only known clock origin is the Unix epoch.
         *
         * At this point, we know that both clock classes have known
         * origins, therefore we also know they share the
         * same origin.
         */
        if (graphMipVersion > 0) {
            if (bt2::isSameClockOrigin(clockCls->origin(), _mRefClockClass->origin(),
                                       graphMipVersion)) {
                throw ClockCorrelationError {
                    ClockCorrelationError::Type::ExpectingOriginKnownGotOtherOrigin, *clockCls,
                    *_mRefClockClass, streamCls};
            }
        }

        break;

    case PropsExpectation::OriginUnknownWithId:
    {
        if (!clockCls) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginUnknownWithIdGotNoClockClass,
                {},
                *_mRefClockClass,
                streamCls};
        }

        if (clockClassHasKnownAndComparableOrigin(*clockCls, graphMipVersion)) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginUnknownWithIdGotKnownOrigin, *clockCls,
                *_mRefClockClass, streamCls};
        }

        if (!clockClassHasKnownAndComparableIdentity(*clockCls, graphMipVersion)) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginUnknownWithIdGotWithoutId, *clockCls,
                *_mRefClockClass, streamCls};
        }

        if (graphMipVersion == 0) {
            if (*clockCls->uuid() != *_mRefClockClass->uuid()) {
                throw ClockCorrelationError {
                    ClockCorrelationError::Type::ExpectingOriginUnknownWithIdGotOtherId, *clockCls,
                    *_mRefClockClass, streamCls};
            }
        } else {
            if (clockCls->identity() != _mRefClockClass->identity()) {
                throw ClockCorrelationError {
                    ClockCorrelationError::Type::ExpectingOriginUnknownWithIdGotOtherId, *clockCls,
                    *_mRefClockClass, streamCls};
            }
        }

        break;
    }

    case PropsExpectation::OriginUnknownWithoutId:
        if (!clockCls) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginUnknownWithoutIdGotNoClockClass,
                {},
                *_mRefClockClass,
                streamCls};
        }

        if (clockCls->libObjPtr() != _mRefClockClass->libObjPtr()) {
            throw ClockCorrelationError {
                ClockCorrelationError::Type::ExpectingOriginUnknownWithoutIdGotOtherClockClass,
                *clockCls, *_mRefClockClass, streamCls};
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
    const std::uint64_t graphMipVersion, bt_clock_correlation_validator_error_type * const type,
    const bt_clock_class ** const actualClockClsOut,
    const bt_clock_class ** const refClockClsOut) noexcept
{
    try {
        reinterpret_cast<bt2ccv::ClockCorrelationValidator *>(validator)->validate(bt2::wrap(msg),
                                                                                   graphMipVersion);
        return true;
    } catch (const bt2ccv::ClockCorrelationError& error) {
        *type = static_cast<bt_clock_correlation_validator_error_type>(error.type());

        if (error.actualClockCls()) {
            *actualClockClsOut = error.actualClockCls()->libObjPtr();
        } else {
            *actualClockClsOut = nullptr;
        }

        if (error.refClockCls()) {
            *refClockClsOut = error.refClockCls()->libObjPtr();
        } else {
            *refClockClsOut = nullptr;
        }

        return false;
    }
}

void bt_clock_correlation_validator_destroy(
    bt_clock_correlation_validator * const validator) noexcept
{
    delete reinterpret_cast<bt2ccv::ClockCorrelationValidator *>(validator);
}
