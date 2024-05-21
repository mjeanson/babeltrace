/*
 * Copyright (c) 2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "cpp-common/bt2c/call.hpp"
#include "cpp-common/bt2s/make-unique.hpp"

#include "ctf-ir.hpp"

namespace ctf {
namespace src {
namespace internal {

void DependentFcMixin::keyFcs(FcSet keyFcs)
{
    _mKeyFcs = std::move(keyFcs);
}

FieldLocMixin::FieldLocMixin(const bt2c::TextLoc& loc) noexcept : _mLoc {loc}
{
}

FcMixin::FcMixin(const bt2c::TextLoc& loc) noexcept : _mLoc {loc}
{
}

FcMixin::FcMixin(const FcDeepType deepType, const bt2c::TextLoc& loc) noexcept :
    _mDeepType {deepType}, _mLoc {loc}
{
}

void ClkClsMixin::sharedLibCls(bt2::ClockClass::Shared cls) noexcept
{
    static_cast<ir::ClkCls<CtfIrMixins>&>(*this).libCls(*cls);
    _mSharedLibCls = std::move(cls);
}

void TraceClsMixin::sharedLibCls(bt2::TraceClass::Shared cls) noexcept
{
    static_cast<ir::TraceCls<CtfIrMixins>&>(*this).libCls(*cls);
    _mSharedLibCls = std::move(cls);
}

} /* namespace internal */

namespace {

bool isStdBitArrayFc(const unsigned int align, const bt2c::DataLen len) noexcept
{
    return align % 8 == 0 && (*len == 8 || *len == 16 || *len == 32 || *len == 64);
}

} /* namespace */

FieldLoc createFieldLoc(const bt2c::TextLoc& loc, bt2s::optional<Scope> origin,
                        FieldLoc::Items items)
{
    return FieldLoc {internal::CtfIrMixins::FieldLoc {loc}, std::move(origin), std::move(items)};
}

std::unique_ptr<FixedLenBitArrayFc>
createFixedLenBitArrayFc(const bt2c::TextLoc& loc, const unsigned int align,
                         const bt2c::DataLen len, const ByteOrder byteOrder,
                         const bt2s::optional<BitOrder>& bitOrder, OptAttrs attrs)
{
    const auto deepType = bt2c::call([align, len, byteOrder, &bitOrder] {
        const auto isRev = FixedLenBitArrayFc::isRev(byteOrder, bitOrder);
        const auto isStd = isStdBitArrayFc(align, len);

        if (byteOrder == ByteOrder::Big) {
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitArrayBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenBitArrayBa16BeRev;
                    case 32:
                        return FcDeepType::FixedLenBitArrayBa32BeRev;
                    case 64:
                        return FcDeepType::FixedLenBitArrayBa64BeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitArrayBa8;
                    case 16:
                        return FcDeepType::FixedLenBitArrayBa16Be;
                    case 32:
                        return FcDeepType::FixedLenBitArrayBa32Be;
                    case 64:
                        return FcDeepType::FixedLenBitArrayBa64Be;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenBitArrayBeRev;
                } else {
                    return FcDeepType::FixedLenBitArrayBe;
                }
            }
        } else {
            /* Little-endian */
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitArrayBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenBitArrayBa16LeRev;
                    case 32:
                        return FcDeepType::FixedLenBitArrayBa32LeRev;
                    case 64:
                        return FcDeepType::FixedLenBitArrayBa64LeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitArrayBa8;
                    case 16:
                        return FcDeepType::FixedLenBitArrayBa16Le;
                    case 32:
                        return FcDeepType::FixedLenBitArrayBa32Le;
                    case 64:
                        return FcDeepType::FixedLenBitArrayBa64Le;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenBitArrayLeRev;
                } else {
                    return FcDeepType::FixedLenBitArrayLe;
                }
            }
        }
    });

    return bt2s::make_unique<FixedLenBitArrayFc>(internal::CtfIrMixins::Fc {deepType, loc},
                                                 internal::CtfIrMixins::FixedLenBitArrayFc {},
                                                 align, len, byteOrder, bitOrder, std::move(attrs));
}

std::unique_ptr<FixedLenBitMapFc>
createFixedLenBitMapFc(const bt2c::TextLoc& loc, const unsigned int align, const bt2c::DataLen len,
                       const ByteOrder byteOrder, FixedLenBitMapFc::Flags flags,
                       const bt2s::optional<BitOrder>& bitOrder, OptAttrs attrs)
{
    const auto deepType = bt2c::call([align, len, byteOrder, &bitOrder] {
        const auto isRev = FixedLenBitArrayFc::isRev(byteOrder, bitOrder);
        const auto isStd = isStdBitArrayFc(align, len);

        if (byteOrder == ByteOrder::Big) {
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitMapBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenBitMapBa16BeRev;
                    case 32:
                        return FcDeepType::FixedLenBitMapBa32BeRev;
                    case 64:
                        return FcDeepType::FixedLenBitMapBa64BeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitMapBa8;
                    case 16:
                        return FcDeepType::FixedLenBitMapBa16Be;
                    case 32:
                        return FcDeepType::FixedLenBitMapBa32Be;
                    case 64:
                        return FcDeepType::FixedLenBitMapBa64Be;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenBitMapBeRev;
                } else {
                    return FcDeepType::FixedLenBitMapBe;
                }
            }
        } else {
            /* Little-endian */
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitMapBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenBitMapBa16LeRev;
                    case 32:
                        return FcDeepType::FixedLenBitMapBa32LeRev;
                    case 64:
                        return FcDeepType::FixedLenBitMapBa64LeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBitMapBa8;
                    case 16:
                        return FcDeepType::FixedLenBitMapBa16Le;
                    case 32:
                        return FcDeepType::FixedLenBitMapBa32Le;
                    case 64:
                        return FcDeepType::FixedLenBitMapBa64Le;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenBitMapLeRev;
                } else {
                    return FcDeepType::FixedLenBitMapLe;
                }
            }
        }
    });

    return bt2s::make_unique<FixedLenBitMapFc>(
        internal::CtfIrMixins::Fc {deepType, loc}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenBitMapFc {}, align, len, byteOrder, std::move(flags),
        bitOrder, std::move(attrs));
}

std::unique_ptr<FixedLenBoolFc>
createFixedLenBoolFc(const bt2c::TextLoc& loc, const unsigned int align, const bt2c::DataLen len,
                     const ByteOrder byteOrder, const bt2s::optional<BitOrder>& bitOrder,
                     OptAttrs attrs)
{
    const auto deepType = bt2c::call([align, len, byteOrder, &bitOrder] {
        const auto isRev = FixedLenBitArrayFc::isRev(byteOrder, bitOrder);
        const auto isStd = isStdBitArrayFc(align, len);

        if (byteOrder == ByteOrder::Big) {
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBoolBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenBoolBa16BeRev;
                    case 32:
                        return FcDeepType::FixedLenBoolBa32BeRev;
                    case 64:
                        return FcDeepType::FixedLenBoolBa64BeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBoolBa8;
                    case 16:
                        return FcDeepType::FixedLenBoolBa16Be;
                    case 32:
                        return FcDeepType::FixedLenBoolBa32Be;
                    case 64:
                        return FcDeepType::FixedLenBoolBa64Be;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenBoolBeRev;
                } else {
                    return FcDeepType::FixedLenBoolBe;
                }
            }
        } else {
            /* Little-endian */
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBoolBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenBoolBa16LeRev;
                    case 32:
                        return FcDeepType::FixedLenBoolBa32LeRev;
                    case 64:
                        return FcDeepType::FixedLenBoolBa64LeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenBoolBa8;
                    case 16:
                        return FcDeepType::FixedLenBoolBa16Le;
                    case 32:
                        return FcDeepType::FixedLenBoolBa32Le;
                    case 64:
                        return FcDeepType::FixedLenBoolBa64Le;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenBoolLeRev;
                } else {
                    return FcDeepType::FixedLenBoolLe;
                }
            }
        }
    });

    return bt2s::make_unique<FixedLenBoolFc>(internal::CtfIrMixins::Fc {deepType, loc},
                                             internal::CtfIrMixins::FixedLenBitArrayFc {},
                                             internal::CtfIrMixins::FixedLenBoolFc {}, align, len,
                                             byteOrder, bitOrder, std::move(attrs));
}

std::unique_ptr<FixedLenFloatFc>
createFixedLenFloatFc(const bt2c::TextLoc& loc, const unsigned int align, const bt2c::DataLen len,
                      const ByteOrder byteOrder, const bt2s::optional<BitOrder>& bitOrder,
                      OptAttrs attrs)
{
    const auto deepType = bt2c::call([align, len, byteOrder, &bitOrder] {
        const auto isRev = FixedLenBitArrayFc::isRev(byteOrder, bitOrder);
        const auto isStd = isStdBitArrayFc(align, len);

        if (byteOrder == ByteOrder::Big) {
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloatBa32BeRev;
                    case 64:
                        return FcDeepType::FixedLenFloatBa64BeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloatBa32Be;
                    case 64:
                        return FcDeepType::FixedLenFloatBa64Be;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloat32BeRev;
                    case 64:
                        return FcDeepType::FixedLenFloat64BeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloat32Be;
                    case 64:
                        return FcDeepType::FixedLenFloat64Be;
                    default:
                        bt_common_abort();
                    }
                }
            }
        } else {
            /* Little-endian */
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloatBa32LeRev;
                    case 64:
                        return FcDeepType::FixedLenFloatBa64LeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloatBa32Le;
                    case 64:
                        return FcDeepType::FixedLenFloatBa64Le;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloat32LeRev;
                    case 64:
                        return FcDeepType::FixedLenFloat64LeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 32:
                        return FcDeepType::FixedLenFloat32Le;
                    case 64:
                        return FcDeepType::FixedLenFloat64Le;
                    default:
                        bt_common_abort();
                    }
                }
            }
        }
    });

    return bt2s::make_unique<FixedLenFloatFc>(internal::CtfIrMixins::Fc {deepType, loc},
                                              internal::CtfIrMixins::FixedLenBitArrayFc {}, align,
                                              len, byteOrder, bitOrder, std::move(attrs));
}

std::unique_ptr<FixedLenUIntFc>
createFixedLenUIntFc(const bt2c::TextLoc& loc, const unsigned int align, const bt2c::DataLen len,
                     const ByteOrder byteOrder, const bt2s::optional<BitOrder>& bitOrder,
                     const DispBase prefDispBase, FixedLenUIntFc::Mappings mappings,
                     UIntFieldRoles roles, OptAttrs attrs)
{
    const auto deepType = bt2c::call([align, len, byteOrder, &bitOrder, &roles] {
        const auto isRev = FixedLenBitArrayFc::isRev(byteOrder, bitOrder);
        const auto isStd = isStdBitArrayFc(align, len);
        const auto hasRole = !roles.empty();

        if (byteOrder == ByteOrder::Big) {
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return hasRole ? FcDeepType::FixedLenUIntBa8RevWithRole :
                                         FcDeepType::FixedLenUIntBa8Rev;
                    case 16:
                        return hasRole ? FcDeepType::FixedLenUIntBa16BeRevWithRole :
                                         FcDeepType::FixedLenUIntBa16BeRev;
                    case 32:
                        return hasRole ? FcDeepType::FixedLenUIntBa32BeRevWithRole :
                                         FcDeepType::FixedLenUIntBa32BeRev;
                    case 64:
                        return hasRole ? FcDeepType::FixedLenUIntBa64BeRevWithRole :
                                         FcDeepType::FixedLenUIntBa64BeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return hasRole ? FcDeepType::FixedLenUIntBa8WithRole :
                                         FcDeepType::FixedLenUIntBa8;
                    case 16:
                        return hasRole ? FcDeepType::FixedLenUIntBa16BeWithRole :
                                         FcDeepType::FixedLenUIntBa16Be;
                    case 32:
                        return hasRole ? FcDeepType::FixedLenUIntBa32BeWithRole :
                                         FcDeepType::FixedLenUIntBa32Be;
                    case 64:
                        return hasRole ? FcDeepType::FixedLenUIntBa64BeWithRole :
                                         FcDeepType::FixedLenUIntBa64Be;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return hasRole ? FcDeepType::FixedLenUIntBeRevWithRole :
                                     FcDeepType::FixedLenUIntBeRev;
                } else {
                    return hasRole ? FcDeepType::FixedLenUIntBeWithRole :
                                     FcDeepType::FixedLenUIntBe;
                }
            }
        } else {
            /* Little-endian */
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return hasRole ? FcDeepType::FixedLenUIntBa8RevWithRole :
                                         FcDeepType::FixedLenUIntBa8Rev;
                    case 16:
                        return hasRole ? FcDeepType::FixedLenUIntBa16LeRevWithRole :
                                         FcDeepType::FixedLenUIntBa16LeRev;
                    case 32:
                        return hasRole ? FcDeepType::FixedLenUIntBa32LeRevWithRole :
                                         FcDeepType::FixedLenUIntBa32LeRev;
                    case 64:
                        return hasRole ? FcDeepType::FixedLenUIntBa64LeRevWithRole :
                                         FcDeepType::FixedLenUIntBa64LeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return hasRole ? FcDeepType::FixedLenUIntBa8WithRole :
                                         FcDeepType::FixedLenUIntBa8;
                    case 16:
                        return hasRole ? FcDeepType::FixedLenUIntBa16LeWithRole :
                                         FcDeepType::FixedLenUIntBa16Le;
                    case 32:
                        return hasRole ? FcDeepType::FixedLenUIntBa32LeWithRole :
                                         FcDeepType::FixedLenUIntBa32Le;
                    case 64:
                        return hasRole ? FcDeepType::FixedLenUIntBa64LeWithRole :
                                         FcDeepType::FixedLenUIntBa64Le;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return hasRole ? FcDeepType::FixedLenUIntLeRevWithRole :
                                     FcDeepType::FixedLenUIntLeRev;
                } else {
                    return hasRole ? FcDeepType::FixedLenUIntLeWithRole :
                                     FcDeepType::FixedLenUIntLe;
                }
            }
        }
    });

    return bt2s::make_unique<FixedLenUIntFc>(
        internal::CtfIrMixins::Fc {deepType, loc}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenIntFc {}, internal::CtfIrMixins::FixedLenUIntFc {}, align,
        len, byteOrder, bitOrder, prefDispBase, std::move(mappings), std::move(roles),
        std::move(attrs));
}

std::unique_ptr<FixedLenSIntFc>
createFixedLenSIntFc(const bt2c::TextLoc& loc, const unsigned int align, const bt2c::DataLen len,
                     const ByteOrder byteOrder, const bt2s::optional<BitOrder>& bitOrder,
                     const DispBase prefDispBase, FixedLenSIntFc::Mappings mappings, OptAttrs attrs)
{
    const auto deepType = bt2c::call([align, len, byteOrder, &bitOrder] {
        const auto isRev = FixedLenBitArrayFc::isRev(byteOrder, bitOrder);
        const auto isStd = isStdBitArrayFc(align, len);

        if (byteOrder == ByteOrder::Big) {
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenSIntBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenSIntBa16BeRev;
                    case 32:
                        return FcDeepType::FixedLenSIntBa32BeRev;
                    case 64:
                        return FcDeepType::FixedLenSIntBa64BeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenSIntBa8;
                    case 16:
                        return FcDeepType::FixedLenSIntBa16Be;
                    case 32:
                        return FcDeepType::FixedLenSIntBa32Be;
                    case 64:
                        return FcDeepType::FixedLenSIntBa64Be;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenSIntBeRev;
                } else {
                    return FcDeepType::FixedLenSIntBe;
                }
            }
        } else {
            /* Little-endian */
            if (isStd) {
                if (isRev) {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenSIntBa8Rev;
                    case 16:
                        return FcDeepType::FixedLenSIntBa16LeRev;
                    case 32:
                        return FcDeepType::FixedLenSIntBa32LeRev;
                    case 64:
                        return FcDeepType::FixedLenSIntBa64LeRev;
                    default:
                        bt_common_abort();
                    }
                } else {
                    switch (*len) {
                    case 8:
                        return FcDeepType::FixedLenSIntBa8;
                    case 16:
                        return FcDeepType::FixedLenSIntBa16Le;
                    case 32:
                        return FcDeepType::FixedLenSIntBa32Le;
                    case 64:
                        return FcDeepType::FixedLenSIntBa64Le;
                    default:
                        bt_common_abort();
                    }
                }
            } else {
                if (isRev) {
                    return FcDeepType::FixedLenSIntLeRev;
                } else {
                    return FcDeepType::FixedLenSIntLe;
                }
            }
        }
    });

    return bt2s::make_unique<FixedLenSIntFc>(
        internal::CtfIrMixins::Fc {deepType, loc}, internal::CtfIrMixins::FixedLenBitArrayFc {},
        internal::CtfIrMixins::FixedLenIntFc {}, align, len, byteOrder, bitOrder, prefDispBase,
        std::move(mappings), std::move(attrs));
}

std::unique_ptr<VarLenUIntFc> createVarLenUIntFc(const bt2c::TextLoc& loc,
                                                 const DispBase prefDispBase,
                                                 VarLenUIntFc::Mappings mappings,
                                                 UIntFieldRoles roles, OptAttrs attrs)
{
    const auto deepType = roles.empty() ? FcDeepType::VarLenUInt : FcDeepType::VarLenUIntWithRole;

    return bt2s::make_unique<VarLenUIntFc>(internal::CtfIrMixins::Fc {deepType, loc},
                                           internal::CtfIrMixins::VarLenIntFc {},
                                           internal::CtfIrMixins::VarLenUIntFc {}, prefDispBase,
                                           std::move(mappings), std::move(roles), std::move(attrs));
}

std::unique_ptr<VarLenSIntFc> createVarLenSIntFc(const bt2c::TextLoc& loc,
                                                 const DispBase prefDispBase,
                                                 VarLenSIntFc::Mappings mappings, OptAttrs attrs)
{
    return bt2s::make_unique<VarLenSIntFc>(internal::CtfIrMixins::Fc {FcDeepType::VarLenSInt, loc},
                                           internal::CtfIrMixins::VarLenIntFc {}, prefDispBase,
                                           std::move(mappings), std::move(attrs));
}

std::unique_ptr<NullTerminatedStrFc>
createNullTerminatedStrFc(const bt2c::TextLoc& loc, const StrEncoding encoding, OptAttrs attrs)
{
    const auto deepType = bt2c::call([encoding] {
        switch (encoding) {
        case StrEncoding::Utf8:
            return FcDeepType::NullTerminatedStrUtf8;
        case StrEncoding::Utf16Be:
        case StrEncoding::Utf16Le:
            return FcDeepType::NullTerminatedStrUtf16;
        case StrEncoding::Utf32Be:
        case StrEncoding::Utf32Le:
            return FcDeepType::NullTerminatedStrUtf32;
        default:
            bt_common_abort();
        }
    });

    return bt2s::make_unique<NullTerminatedStrFc>(internal::CtfIrMixins::Fc {deepType, loc},
                                                  encoding, std::move(attrs));
}

std::unique_ptr<StaticLenStrFc> createStaticLenStrFc(const bt2c::TextLoc& loc,
                                                     const std::size_t len,
                                                     const StrEncoding encoding, OptAttrs attrs)
{
    return bt2s::make_unique<StaticLenStrFc>(
        internal::CtfIrMixins::Fc {FcDeepType::StaticLenStr, loc},
        internal::CtfIrMixins::StaticLenStrFc {}, len, encoding, std::move(attrs));
}

std::unique_ptr<DynLenStrFc> createDynLenStrFc(const bt2c::TextLoc& loc, FieldLoc lenFieldLoc,
                                               const StrEncoding encoding, OptAttrs attrs)
{
    return bt2s::make_unique<DynLenStrFc>(internal::CtfIrMixins::Fc {FcDeepType::DynLenStr, loc},
                                          internal::CtfIrMixins::DynLenStrFc {},
                                          std::move(lenFieldLoc), encoding, std::move(attrs));
}

std::unique_ptr<StaticLenBlobFc> createStaticLenBlobFc(const bt2c::TextLoc& loc,
                                                       const std::size_t len, std::string mediaType,
                                                       const bool hasMetadataStreamUuidRole,
                                                       OptAttrs attrs)
{
    const auto deepType = hasMetadataStreamUuidRole ?
                              FcDeepType::StaticLenBlobWithMetadataStreamUuidRole :
                              FcDeepType::StaticLenBlob;

    return bt2s::make_unique<StaticLenBlobFc>(
        internal::CtfIrMixins::Fc {deepType, loc}, internal::CtfIrMixins::StaticLenBlobFc {}, len,
        std::move(mediaType), hasMetadataStreamUuidRole, std::move(attrs));
}

std::unique_ptr<DynLenBlobFc> createDynLenBlobFc(const bt2c::TextLoc& loc, FieldLoc lenFieldLoc,
                                                 std::string mediaType, OptAttrs attrs)
{
    return bt2s::make_unique<DynLenBlobFc>(internal::CtfIrMixins::Fc {FcDeepType::DynLenBlob, loc},
                                           internal::CtfIrMixins::DynLenBlobFc {},
                                           std::move(lenFieldLoc), std::move(mediaType),
                                           std::move(attrs));
}

std::unique_ptr<StaticLenArrayFc> createStaticLenArrayFc(const bt2c::TextLoc& loc,
                                                         const std::size_t len, Fc::UP elemFc,
                                                         const unsigned int minAlign,
                                                         const bool hasMetadataStreamUuidRole,
                                                         OptAttrs attrs)
{
    const auto deepType = hasMetadataStreamUuidRole ?
                              FcDeepType::StaticLenArrayWithMetadataStreamUuidRole :
                              FcDeepType::StaticLenArray;

    return bt2s::make_unique<StaticLenArrayFc>(internal::CtfIrMixins::Fc {deepType, loc},
                                               internal::CtfIrMixins::StaticLenArrayFc {}, len,
                                               std::move(elemFc), minAlign, std::move(attrs));
}

std::unique_ptr<DynLenArrayFc> createDynLenArrayFc(const bt2c::TextLoc& loc, FieldLoc lenFieldLoc,
                                                   Fc::UP elemFc, const unsigned int minAlign,
                                                   OptAttrs attrs)
{
    return bt2s::make_unique<DynLenArrayFc>(
        internal::CtfIrMixins::Fc {FcDeepType::DynLenArray, loc},
        internal::CtfIrMixins::DynLenArrayFc {}, std::move(lenFieldLoc), std::move(elemFc),
        minAlign, std::move(attrs));
}

StructFieldMemberCls createStructFieldMemberCls(std::string name, Fc::UP fc, OptAttrs attrs)
{
    return StructFieldMemberCls {internal::CtfIrMixins::StructFieldMemberCls {}, std::move(name),
                                 std::move(fc), std::move(attrs)};
}

std::unique_ptr<StructFc> createStructFc(const bt2c::TextLoc& loc,
                                         StructFc::MemberClasses&& memberClasses,
                                         const unsigned int minAlign, OptAttrs attrs)
{
    return bt2s::make_unique<StructFc>(internal::CtfIrMixins::Fc {FcDeepType::Struct, loc},
                                       internal::CtfIrMixins::StructFc {}, std::move(memberClasses),
                                       minAlign, std::move(attrs));
}

std::unique_ptr<OptionalWithBoolSelFc> createOptionalFc(const bt2c::TextLoc& loc, Fc::UP fc,
                                                        FieldLoc selFieldLoc, OptAttrs attrs)
{
    return bt2s::make_unique<OptionalWithBoolSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::OptionalWithBoolSel, loc},
        internal::CtfIrMixins::OptionalFc {}, internal::CtfIrMixins::OptionalWithBoolSelFc {},
        std::move(fc), std::move(selFieldLoc), std::move(attrs));
}

std::unique_ptr<OptionalWithUIntSelFc> createOptionalFc(const bt2c::TextLoc& loc, Fc::UP fc,
                                                        FieldLoc selFieldLoc,
                                                        UIntRangeSet selFieldRanges, OptAttrs attrs)
{
    return bt2s::make_unique<OptionalWithUIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::OptionalWithUIntSel, loc},
        internal::CtfIrMixins::OptionalFc {}, internal::CtfIrMixins::OptionalWithIntSelFc {},
        internal::CtfIrMixins::OptionalWithUIntSelFc {}, std::move(fc), std::move(selFieldLoc),
        std::move(selFieldRanges), std::move(attrs));
}

std::unique_ptr<OptionalWithSIntSelFc> createOptionalFc(const bt2c::TextLoc& loc, Fc::UP fc,
                                                        FieldLoc selFieldLoc,
                                                        SIntRangeSet selFieldRanges, OptAttrs attrs)
{
    return bt2s::make_unique<OptionalWithSIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::OptionalWithSIntSel, loc},
        internal::CtfIrMixins::OptionalFc {}, internal::CtfIrMixins::OptionalWithIntSelFc {},
        internal::CtfIrMixins::OptionalWithSIntSelFc {}, std::move(fc), std::move(selFieldLoc),
        std::move(selFieldRanges), std::move(attrs));
}

VariantWithUIntSelFc::Opt createVariantFcOpt(Fc::UP fc, UIntRangeSet selFieldRanges,
                                             bt2s::optional<std::string> name, OptAttrs attrs)
{
    return VariantWithUIntSelFc::Opt {internal::CtfIrMixins::VariantFcOpt {}, std::move(fc),
                                      std::move(selFieldRanges), std::move(name), std::move(attrs)};
}

VariantWithSIntSelFc::Opt createVariantFcOpt(Fc::UP fc, SIntRangeSet selFieldRanges,
                                             bt2s::optional<std::string> name, OptAttrs attrs)
{
    return VariantWithSIntSelFc::Opt {internal::CtfIrMixins::VariantFcOpt {}, std::move(fc),
                                      std::move(selFieldRanges), std::move(name), std::move(attrs)};
}

std::unique_ptr<VariantWithUIntSelFc> createVariantFc(const bt2c::TextLoc& loc,
                                                      VariantWithUIntSelFc::Opts&& opts,
                                                      FieldLoc selFieldLoc, OptAttrs attrs)
{
    return bt2s::make_unique<VariantWithUIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::VariantWithUIntSel, loc},
        internal::CtfIrMixins::VariantFc {}, internal::CtfIrMixins::VariantWithUIntSelFc {},
        std::move(opts), std::move(selFieldLoc), std::move(attrs));
}

std::unique_ptr<VariantWithSIntSelFc> createVariantFc(const bt2c::TextLoc& loc,
                                                      VariantWithSIntSelFc::Opts&& opts,
                                                      FieldLoc selFieldLoc, OptAttrs attrs)
{
    return bt2s::make_unique<VariantWithSIntSelFc>(
        internal::CtfIrMixins::Fc {FcDeepType::VariantWithSIntSel, loc},
        internal::CtfIrMixins::VariantFc {}, internal::CtfIrMixins::VariantWithSIntSelFc {},
        std::move(opts), std::move(selFieldLoc), std::move(attrs));
}

ClkCls::SP createClkCls(std::string id, const unsigned long long freq,
                        bt2s::optional<std::string> ns, bt2s::optional<std::string> name,
                        bt2s::optional<std::string> uid, const ClkOffset& offset,
                        bt2s::optional<ClkOrigin> origin, bt2s::optional<std::string> descr,
                        bt2s::optional<unsigned long long> precision,
                        bt2s::optional<unsigned long long> accuracy, OptAttrs attrs)
{
    return std::make_shared<ClkCls>(internal::CtfIrMixins::ClkCls {}, std::move(id), freq,
                                    std::move(ns), std::move(name), std::move(uid), offset,
                                    std::move(origin), std::move(descr), std::move(precision),
                                    std::move(accuracy), std::move(attrs));
}

std::unique_ptr<EventRecordCls>
createEventRecordCls(const unsigned long long id, bt2s::optional<std::string> ns,
                     bt2s::optional<std::string> name, bt2s::optional<std::string> uid,
                     Fc::UP specCtxFc, Fc::UP payloadFc, OptAttrs attrs)
{
    return bt2s::make_unique<EventRecordCls>(
        internal::CtfIrMixins::EventRecordCls {}, id, std::move(ns), std::move(name),
        std::move(uid), std::move(specCtxFc), std::move(payloadFc), std::move(attrs));
}

std::unique_ptr<DataStreamCls>
createDataStreamCls(const unsigned long long id, bt2s::optional<std::string> ns,
                    bt2s::optional<std::string> name, bt2s::optional<std::string> uid,
                    Fc::UP pktCtxFc, Fc::UP eventRecordHeaderFc, Fc::UP commonEventRecordCtxFc,
                    ClkCls::SP defClkCls, OptAttrs attrs)
{
    return bt2s::make_unique<DataStreamCls>(
        internal::CtfIrMixins::DataStreamCls {}, id, std::move(ns), std::move(name), std::move(uid),
        std::move(pktCtxFc), std::move(eventRecordHeaderFc), std::move(commonEventRecordCtxFc),
        std::move(defClkCls), std::move(attrs));
}

std::unique_ptr<TraceCls> createTraceCls(bt2s::optional<std::string> ns,
                                         bt2s::optional<std::string> name,
                                         bt2s::optional<std::string> uid,
                                         bt2::ConstMapValue::Shared env, Fc::UP pktHeaderFc,
                                         OptAttrs attrs)
{
    return bt2s::make_unique<TraceCls>(internal::CtfIrMixins::TraceCls {}, std::move(ns),
                                       std::move(name), std::move(uid), std::move(env),
                                       std::move(pktHeaderFc), std::move(attrs));
}

} /* namespace src */
} /* namespace ctf */
