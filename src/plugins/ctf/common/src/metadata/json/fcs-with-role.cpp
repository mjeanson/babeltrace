/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "cpp-common/bt2c/contains.hpp"

#include "fcs-with-role.hpp"

namespace ctf {
namespace src {
namespace {

/*
 * Helper of fcsWithRole().
 */
class Finder final : public ConstFcVisitor
{
public:
    explicit Finder(const UIntFieldRoles& roles, const bool withMetadataStreamUuidRole) :
        _mRoles {&roles}, _mWithMetadataStreamUuidRole {withMetadataStreamUuidRole}
    {
    }

    std::unordered_set<const Fc *> takeFcs() noexcept
    {
        return std::move(_mFcs);
    }

private:
    void visit(const FixedLenUIntFc& fc) override
    {
        this->_tryAddUIntFc(fc);
    }

    void visit(const VarLenUIntFc& fc) override
    {
        this->_tryAddUIntFc(fc);
    }

    void visit(const StaticLenBlobFc& fc) override
    {
        if (_mWithMetadataStreamUuidRole && fc.hasMetadataStreamUuidRole()) {
            _mFcs.emplace(&fc);
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
            memberCls.fc().accept(*this);
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
    void _tryAddUIntFc(const UIntFcT& fc)
    {
        for (const auto role : fc.roles()) {
            if (bt2c::contains(*_mRoles, role)) {
                _mFcs.emplace(&fc);
            }
        }
    }

    void _visit(const ArrayFc& fc)
    {
        fc.elemFc().accept(*this);
    }

    void _visit(const OptionalFc& fc)
    {
        fc.fc().accept(*this);
    }

    template <typename VarFcT>
    void _visitVariantFc(const VarFcT& fc)
    {
        for (auto& opt : fc) {
            opt.fc().accept(*this);
        }
    }

    const UIntFieldRoles *_mRoles;
    bool _mWithMetadataStreamUuidRole;
    std::unordered_set<const Fc *> _mFcs;
};

} /* namespace */

std::unordered_set<const Fc *> fcsWithRole(const Fc& fc, const UIntFieldRoles& roles,
                                           const bool withMetadataStreamUuidRole)
{
    Finder finder {roles, withMetadataStreamUuidRole};

    fc.accept(finder);
    return finder.takeFcs();
}

} /* namespace src */
} /* namespace ctf */
