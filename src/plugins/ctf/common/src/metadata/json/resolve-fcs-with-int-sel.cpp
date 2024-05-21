/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <unordered_map>
#include <utility>

#include "common/assert.h"
#include "cpp-common/bt2c/logging.hpp"

#include "key-fc-types.hpp"
#include "resolve-fcs-with-int-sel.hpp"

namespace ctf {
namespace src {
namespace {

SIntRangeSet sIntRangeSetFromUIntRangeSet(const UIntRangeSet& uIntRanges)
{
    SIntRangeSet::Set sIntRanges;

    for (auto& uIntRange : uIntRanges) {
        sIntRanges.emplace(SIntRangeSet::Range {static_cast<SIntRangeSet::Val>(uIntRange.lower()),
                                                static_cast<SIntRangeSet::Val>(uIntRange.upper())});
    }

    return SIntRangeSet {std::move(sIntRanges)};
}

/*
 * Helper of resolveFcsWithIntSel().
 */
class Resolver final : public FcVisitor
{
public:
    explicit Resolver(const KeyFcTypes& keyFcTypes, const bt2c::Logger& parentLogger) :
        _mKeyFcTypes {&keyFcTypes}, _mLogger {parentLogger, "PLUGIN/CTF/CTF-2-RES-FCS-WITH-INT-SEL"}
    {
    }

private:
    void visit(StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(DynLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(StructFc& fc) override
    {
        for (auto& memberCls : fc) {
            try {
                memberCls.fc(this->_resolveFc(memberCls.takeFc()));
                memberCls.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                    memberCls.fc().loc(), "Invalid structure field member class.");
            }
        }
    }

    void visit(OptionalWithBoolSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(OptionalWithUIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(OptionalWithSIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(VariantWithUIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    void visit(VariantWithSIntSelFc& fc) override
    {
        this->_visitVariantFc(fc);
    }

    void _visit(ArrayFc& fc)
    {
        try {
            fc.elemFc(this->_resolveFc(fc.takeElemFc()));
            fc.elemFc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid element field class of array field class.");
        }
    }

    void _visit(OptionalFc& fc)
    {
        try {
            fc.fc(this->_resolveFc(fc.takeFc()));
            fc.fc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid field class of optional field class.");
        }
    }

    template <typename VarFcT>
    void _visitVariantFc(VarFcT& fc)
    {
        for (auto& opt : fc) {
            try {
                opt.fc(this->_resolveFc(opt.takeFc()));
                opt.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(opt.fc().loc(),
                                                             "Invalid variant field class option.");
            }
        }
    }

    Fc::UP _resolveFc(Fc::UP fc)
    {
        if (!fc->isOptionalWithUIntSel() && !fc->isVariantWithUIntSel()) {
            /* Not a candidate for replacement: return as is */
            return fc;
        }

        const auto keyFcType = _mKeyFcTypes->at(fc.get());

        if (keyFcType == KeyFcType::UInt) {
            /* Type of `*fc` is already correct: return as is */
            return fc;
        }

        BT_ASSERT(keyFcType == KeyFcType::SInt);

        /*
         * The goal here is to create an `OptionalWithSIntSel` or a
         * `VariantWithSIntSel` field class from an
         * `OptionalWithUIntSel` or a `VariantWithUIntSel` field class,
         * stealing (moving) as much as possible from `*fc` as it will
         * be discarded anyway (explaining all the take*()
         * method calls).
         *
         * sIntRangeSetFromUIntRangeSet() converts the selector field
         * ranges from unsigned to signed.
         */
        if (fc->isOptionalWithUIntSel()) {
            auto& optionalFc = fc->asOptionalWithUIntSel();

            return createOptionalFc(
                optionalFc.loc(), optionalFc.takeFc(), optionalFc.takeSelFieldLoc(),
                sIntRangeSetFromUIntRangeSet(optionalFc.selFieldRanges()), optionalFc.takeAttrs());
        } else {
            BT_ASSERT(fc->isVariantWithUIntSel());

            auto& varFc = fc->asVariantWithUIntSel();
            VariantWithSIntSelFc::Opts newOpts;

            for (auto& opt : varFc) {
                newOpts.emplace_back(createVariantFcOpt(
                    opt.takeFc(), sIntRangeSetFromUIntRangeSet(opt.selFieldRanges()),
                    opt.takeName(), opt.takeAttrs()));
            }

            return createVariantFc(varFc.loc(), std::move(newOpts), varFc.takeSelFieldLoc(),
                                   varFc.takeAttrs());
        }
    }

    const KeyFcTypes *_mKeyFcTypes;
    bt2c::Logger _mLogger;
};

} /* namespace */

void resolveFcsWithIntSel(Fc& scopeFc, const Scope scope, const Fc * const pktHeaderFc,
                          const Fc * const pktCtxFc, const Fc * const eventRecordHeaderFc,
                          const Fc * const commonEventRecordCtxFc,
                          const Fc * const specEventRecordCtxFc,
                          const Fc * const eventRecordPayloadFc, const bt2c::Logger& logger)
{
    const auto theKeyFcTypes =
        keyFcTypes(scopeFc, scope, pktHeaderFc, pktCtxFc, eventRecordHeaderFc,
                   commonEventRecordCtxFc, specEventRecordCtxFc, eventRecordPayloadFc, logger);
    Resolver resolver {theKeyFcTypes, logger};

    scopeFc.accept(resolver);
}

} /* namespace src */
} /* namespace ctf */
