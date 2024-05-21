/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/assert.h"
#include "common/common.h"
#include "cpp-common/bt2c/logging.hpp"

#include "normalize-field-locs.hpp"

namespace ctf {
namespace src {
namespace {

/*
 * Helper of normalizeFieldLocs().
 */
class Normalizer final : public FcVisitor
{
public:
    explicit Normalizer(const Scope scope, const bt2c::Logger& parentLogger) :
        _mScope {scope}, _mLogger {parentLogger, "PLUGIN/CTF/CTF-2-NORMALIZE-FIELD-LOCS"}
    {
    }

private:
    void visit(StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(DynLenArrayFc& fc) override
    {
        fc.lenFieldLoc(this->_normalizeFieldLoc(fc.lenFieldLoc()));
        this->_visit(fc);
    }

    void visit(DynLenStrFc& fc) override
    {
        fc.lenFieldLoc(this->_normalizeFieldLoc(fc.lenFieldLoc()));
    }

    void visit(DynLenBlobFc& fc) override
    {
        fc.lenFieldLoc(this->_normalizeFieldLoc(fc.lenFieldLoc()));
    }

    void visit(StructFc& fc) override
    {
        for (auto& memberCls : fc) {
            _mMemberNames.push_back(&memberCls.name());

            try {
                memberCls.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                    memberCls.fc().loc(), "Invalid structure field member class.");
            }

            _mMemberNames.pop_back();
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

    void visit(OptionalWithSIntSelFc&) override
    {
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void visit(VariantWithUIntSelFc& fc) override
    {
        fc.selFieldLoc(this->_normalizeFieldLoc(fc.selFieldLoc()));

        for (auto& opt : fc) {
            try {
                opt.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(opt.fc().loc(),
                                                             "Invalid variant field class option.");
            }
        }
    }

    void visit(VariantWithSIntSelFc&) override
    {
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void _visit(ArrayFc& fc)
    {
        try {
            fc.elemFc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid element field class of array field class.");
        }
    }

    void _visit(OptionalFc& fc)
    {
        fc.selFieldLoc(this->_normalizeFieldLoc(fc.selFieldLoc()));

        try {
            fc.fc().accept(*this);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid field class of optional field class.");
        }
    }

    /*
     * Returns the normalized version of `fieldLoc`.
     */
    FieldLoc _normalizeFieldLoc(const FieldLoc& fieldLoc) const
    {
        if (fieldLoc.origin()) {
            /* Already absolute */
            return fieldLoc;
        }

        /*
         * First remove non-leading "parent" field location items.
         *
         * For example (using a file system notation):
         *
         * • `../../meow/mix/../glue/all` → `../../meow/glue/all`.
         * • `hello/../../world` → `../world`.
         */
        const auto tmpItems = bt2c::call([&fieldLoc] {
            FieldLoc::Items retItems;

            for (auto& item : fieldLoc.items()) {
                if (retItems.empty()) {
                    retItems.push_back(item);
                } else {
                    if (item) {
                        retItems.push_back(item);
                    } else {
                        /* Go back to known parent */
                        retItems.pop_back();
                    }
                }
            }

            return retItems;
        });

        /*
         * Create absolute field location items.
         *
         * Example 1: with leading "parent" items
         * ──────────────────────────────────────
         * Given the temporary items `../meow/mix` and the current
         * member names `/red/blue/green` (`green` being the name of the
         * dependent field class having the location `fieldLoc`), then
         * after the loop below:
         *
         *     /red/blue/green
         *          ▲
         *          memberNameEndIt
         *
         *     ../meow/mix
         *        ▲
         *        tmpItemIt
         *
         * Final, absolute items:
         *
         *     /red/meow/mix
         *
         * Example 2: without leading "parent" items
         * ─────────────────────────────────────────
         * Given the temporary items `meow/mix` and the current member
         * names `/red/blue/green` (`green` being the name of the
         * dependent field class having the location `fieldLoc`), then
         * after the loop below:
         *
         *     /red/blue/green
         *               ▲
         *               memberNameEndIt
         *
         *     meow/mix
         *     ▲
         *     tmpItemIt
         *
         * Final, absolute items:
         *
         *     /red/blue/meow/mix
         */
        BT_ASSERT(!_mMemberNames.empty());

        auto tmpItemIt = tmpItems.begin();
        auto memberNameEndIt = _mMemberNames.end() - 1;

        for (; tmpItemIt != tmpItems.end(); ++tmpItemIt) {
            if (*tmpItemIt) {
                /* End of leading "parent" items */
                break;
            }

            if (memberNameEndIt == _mMemberNames.begin()) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, fieldLoc.loc(),
                    "Invalid field location: too many \"parent\" path items.");
            }

            --memberNameEndIt;
        }

        FieldLoc::Items items;

        for (auto memberNameIt = _mMemberNames.begin(); memberNameIt != memberNameEndIt;
             ++memberNameIt) {
            items.push_back(**memberNameIt);
        }

        for (; tmpItemIt != tmpItems.end(); ++tmpItemIt) {
            items.push_back(*tmpItemIt);
        }

        /* Create absolute field location */
        return createFieldLoc(fieldLoc.loc(), _mScope, std::move(items));
    }

    std::vector<const std::string *> _mMemberNames;
    Scope _mScope;
    bt2c::Logger _mLogger;
};

} /* namespace */

void normalizeFieldLocs(Fc& scopeFc, const Scope scope, const bt2c::Logger& parentLogger)
{
    Normalizer normalizer {scope, parentLogger};

    scopeFc.accept(normalizer);
}

} /* namespace src */
} /* namespace ctf */
