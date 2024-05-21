/*
 * Copyright (c) 2022-2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "cpp-common/bt2c/contains.hpp"

#include "strings.hpp"
#include "validate-scope-fc-roles.hpp"

namespace ctf {
namespace src {
namespace {

const char *validScopeNamesForRole(const UIntFieldRole role) noexcept
{
    switch (role) {
    case UIntFieldRole::PktMagicNumber:
    case UIntFieldRole::DataStreamClsId:
    case UIntFieldRole::DataStreamId:
        return "a packet header";
    case UIntFieldRole::DefClkTs:
        return "a packet context or an event record header";
    case UIntFieldRole::PktTotalLen:
    case UIntFieldRole::PktContentLen:
    case UIntFieldRole::PktEndDefClkTs:
    case UIntFieldRole::DiscEventRecordCounterSnap:
    case UIntFieldRole::PktSeqNum:
        return "a packet context";
    case UIntFieldRole::EventRecordClsId:
        return "an event record header";
    default:
        bt_common_abort();
    }
}

const char *uIntFcRoleJsonStr(const UIntFieldRole role) noexcept
{
    switch (role) {
    case UIntFieldRole::PktMagicNumber:
        return jsonstr::pktMagicNumber;
    case UIntFieldRole::DataStreamClsId:
        return jsonstr::dataStreamClsId;
    case UIntFieldRole::DataStreamId:
        return jsonstr::dataStreamId;
    case UIntFieldRole::PktTotalLen:
        return jsonstr::pktTotalLen;
    case UIntFieldRole::PktContentLen:
        return jsonstr::pktContentLen;
    case UIntFieldRole::DefClkTs:
        return jsonstr::defClkTs;
    case UIntFieldRole::PktEndDefClkTs:
        return jsonstr::pktEndDefClkTs;
    case UIntFieldRole::DiscEventRecordCounterSnap:
        return jsonstr::discEventRecordCounterSnap;
    case UIntFieldRole::PktSeqNum:
        return jsonstr::pktSeqNum;
    case UIntFieldRole::EventRecordClsId:
        return jsonstr::eventRecordClsId;
    default:
        bt_common_abort();
    }
}

/*
 * Helper of validateScopeFcRoles().
 */
class Validator final : public ConstFcVisitor
{
public:
    explicit Validator(const UIntFieldRoles& allowedRoles, const bool allowMetadataStreamUuidRole,
                       const bt2c::Logger& parentLogger) :
        _mLogger {parentLogger, "PLUGIN/CTF/CTF-2-VALIDATE-SCOPE-FC-ROLES"},
        _mAllowedRoles {&allowedRoles}, _mAllowMetadataStreamUuidRole {allowMetadataStreamUuidRole}
    {
    }

private:
    void visit(const FixedLenUIntFc& fc) override
    {
        this->_validateUIntFc(fc);
    }

    void visit(const VarLenUIntFc& fc) override
    {
        this->_validateUIntFc(fc);
    }

    void visit(const StaticLenBlobFc& fc) override
    {
        if (fc.asStaticLenBlob().hasMetadataStreamUuidRole() && !_mAllowMetadataStreamUuidRole) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, fc.loc(),
                "Static-length BLOB field class may not have the `{}` role here "
                "(only valid within a packet header field class).",
                jsonstr::metadataStreamUuid);
        }
    }

    void visit(const StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const DynLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const StructFc& fc) override
    {
        for (auto& memberCls : fc) {
            try {
                memberCls.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                    memberCls.fc().loc(), "Invalid structure field member class.");
            }
        }
    }

    void visit(const OptionalWithBoolSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const OptionalWithUIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const OptionalWithSIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const VariantWithUIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    void visit(const VariantWithSIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    template <typename UIntFcT>
    void _validateUIntFc(const UIntFcT& fc) const
    {
        for (const auto role : fc.roles()) {
            if (!bt2c::contains(*_mAllowedRoles, role)) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, fc.loc(),
                    "Unsigned integer field class may not have the `{}` role here "
                    "(only valid within {} field class).",
                    uIntFcRoleJsonStr(role), validScopeNamesForRole(role));
            }
        }
    }

    void _visit(const ArrayFc& fc)
    {
        try {
            fc.elemFc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid element field class of array field class.");
        }
    }

    void _visit(const OptionalFc& fc)
    {
        try {
            fc.fc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid field class of optional field class.");
        }
    }

    template <typename VarFcT>
    void _visitVariantFc(const VarFcT& fc)
    {
        for (auto& opt : fc) {
            try {
                opt.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(opt.fc().loc(),
                                                             "Invalid variant field class option.");
            }
        }
    }

    bt2c::Logger _mLogger;
    const UIntFieldRoles *_mAllowedRoles;
    bool _mAllowMetadataStreamUuidRole;
};

} /* namespace */

void validateScopeFcRoles(const Fc& fc, const UIntFieldRoles& allowedRoles,
                          const bool allowMetadataStreamUuidRole, const bt2c::Logger& parentLogger)
{
    Validator validator {allowedRoles, allowMetadataStreamUuidRole, parentLogger};

    fc.accept(validator);
}

} /* namespace src */
} /* namespace ctf */
