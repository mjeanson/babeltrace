/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "common/assert.h"
#include "cpp-common/bt2c/contains.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2s/optional.hpp"

#include "../ctf-ir.hpp"
#include "ctf-2-fc-builder.hpp"
#include "strings.hpp"
#include "utils.hpp"

namespace ctf {
namespace src {
namespace {

/*
 * Creates and returns the set of unsigned integer field roles of the
 * JSON unsigned integer field class value `jsonFc`.
 */
UIntFieldRoles uIntFieldRolesOfJsonUIntFc(const bt2c::JsonObjVal& jsonFc)
{
    UIntFieldRoles roles;
    const auto jsonRoles = jsonFc[jsonstr::roles];

    if (!jsonRoles) {
        /* No roles */
        return roles;
    }

    for (auto& jsonRole : jsonRoles->asArray()) {
        auto& roleName = *jsonRole->asStr();

        if (roleName == jsonstr::dataStreamClsId) {
            roles.insert(UIntFieldRole::DataStreamClsId);
        } else if (roleName == jsonstr::dataStreamId) {
            roles.insert(UIntFieldRole::DataStreamId);
        } else if (roleName == jsonstr::pktMagicNumber) {
            roles.insert(UIntFieldRole::PktMagicNumber);
        } else if (roleName == jsonstr::defClkTs) {
            roles.insert(UIntFieldRole::DefClkTs);
        } else if (roleName == jsonstr::discEventRecordCounterSnap) {
            roles.insert(UIntFieldRole::DiscEventRecordCounterSnap);
        } else if (roleName == jsonstr::pktContentLen) {
            roles.insert(UIntFieldRole::PktContentLen);
        } else if (roleName == jsonstr::pktTotalLen) {
            roles.insert(UIntFieldRole::PktTotalLen);
        } else if (roleName == jsonstr::pktEndDefClkTs) {
            roles.insert(UIntFieldRole::PktEndDefClkTs);
        } else if (roleName == jsonstr::pktSeqNum) {
            roles.insert(UIntFieldRole::PktSeqNum);
        } else {
            BT_ASSERT(roleName == jsonstr::eventRecordClsId);
            roles.insert(UIntFieldRole::EventRecordClsId);
        }
    }

    return roles;
}

/*
 * Creates and returns an integer range set (of type
 * `IntRangeSet<ValT>`) from the JSON integer range set
 * value `jsonIntRangeSet`.
 */
template <typename ValT>
IntRangeSet<ValT> intRangeSetFromJsonIntRangeSet(const bt2c::JsonArrayVal& jsonIntRangeSet)
{
    typename IntRangeSet<ValT>::Set ranges;

    for (auto& jsonRange : jsonIntRangeSet) {
        auto& jsonRangeArray = jsonRange->asArray();

        BT_ASSERT(jsonRangeArray.size() == 2);
        ranges.emplace(
            IntRangeSet<ValT>::Range::makeTemp(rawIntValFromJsonIntVal<ValT>(jsonRangeArray[0]),
                                               rawIntValFromJsonIntVal<ValT>(jsonRangeArray[1])));
    }

    return IntRangeSet<ValT> {std::move(ranges)};
}

/*
 * Creates and returns the integer field class mappings (of type
 * `IntFcT::Mappings`) of the JSON integer field class value `jsonFc`.
 */
template <typename IntFcT>
typename IntFcT::Mappings intFcMappingsOfJsonIntFc(const bt2c::JsonObjVal& jsonFc)
{
    typename IntFcT::Mappings mappings;

    if (const auto jsonMappings = jsonFc[jsonstr::mappings]) {
        /* At least one mapping */
        for (auto& keyJsonIntRangesPair : jsonMappings->asObj()) {
            mappings.insert(std::make_pair(keyJsonIntRangesPair.first,
                                           intRangeSetFromJsonIntRangeSet<typename IntFcT::Val>(
                                               keyJsonIntRangesPair.second->asArray())));
        }
    }

    return mappings;
}

/*
 * Returns the preferred display base of the JSON integer field class
 * value `jsonFc`.
 */
DispBase prefDispBaseOfJsonIntFc(const bt2c::JsonObjVal& jsonFc) noexcept
{
    return static_cast<DispBase>(jsonFc.rawVal(jsonstr::prefDispBase, 10ULL));
}

/*
 * Creates and returns a fixed-length integer field class from the JSON
 * fixed-length integer field class value `jsonFc` and the
 * other parameters.
 */
Fc::UP fcFromJsonFixedLenIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                               const unsigned int align, const bt2c::DataLen len,
                               const ByteOrder byteOrder, const BitOrder bitOrder, OptAttrs&& attrs)
{
    /* Preferred display base */
    const auto prefDispBase = prefDispBaseOfJsonIntFc(jsonFc);

    /* Create field class */
    if (type == jsonstr::fixedLenUInt) {
        return createFixedLenUIntFc(jsonFc.loc(), align, len, byteOrder, bitOrder, prefDispBase,
                                    intFcMappingsOfJsonIntFc<FixedLenUIntFc>(jsonFc),
                                    uIntFieldRolesOfJsonUIntFc(jsonFc), std::move(attrs));
    } else {
        BT_ASSERT(type == jsonstr::fixedLenSInt);
        return createFixedLenSIntFc(jsonFc.loc(), align, len, byteOrder, bitOrder, prefDispBase,
                                    intFcMappingsOfJsonIntFc<FixedLenSIntFc>(jsonFc),
                                    std::move(attrs));
    }
}

/*
 * Returns the length of the JSON field class value `jsonFc`.
 */
unsigned long long lenOfJsonFc(const bt2c::JsonObjVal& jsonFc) noexcept
{
    return jsonFc.rawUIntVal(jsonstr::len);
}

/*
 * Creates and returns the fixed-length bit map field class flags (of type
 * of the JSON integer field class value `jsonFc`.
 */
FixedLenBitMapFc::Flags fixedLenBitMapFlagsOfJsonFixedLenBitMapFc(const bt2c::JsonObjVal& jsonFc)
{
    using Val = FixedLenBitMapFc::Flags::value_type::second_type::Val;

    FixedLenBitMapFc::Flags flags;
    const auto jsonFlags = jsonFc[jsonstr::flags];

    for (auto& keyJsonIntRangesPair : jsonFlags->asObj()) {
        flags.insert(std::make_pair(
            keyJsonIntRangesPair.first,
            intRangeSetFromJsonIntRangeSet<Val>(keyJsonIntRangesPair.second->asArray())));
    }

    return flags;
}

/*
 * Creates and returns a fixed-length bit array field class from the
 * JSON fixed-length bit array field class value `jsonFc` and the other
 * parameters.
 */
Fc::UP fcFromJsonFixedLenBitArrayFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                    OptAttrs&& attrs)
{
    /* Alignment */
    const auto align = jsonFc.rawVal(jsonstr::align, 1ULL);

    /* Length */
    const auto len = bt2c::DataLen::fromBits(lenOfJsonFc(jsonFc));

    /* Byte order */
    const auto byteOrder = jsonFc.rawStrVal(jsonstr::byteOrder) == jsonstr::littleEndian ?
                               ByteOrder::Little :
                               ByteOrder::Big;

    /* Bit order */
    const auto bitOrder = bt2c::call([&jsonFc, byteOrder] {
        const auto bitOrderStr = optStrOfObj(jsonFc, jsonstr::bitOrder);

        if (!bitOrderStr) {
            return byteOrder == ByteOrder::Little ? BitOrder::FirstToLast : BitOrder::LastToFirst;
        }

        return *bitOrderStr == jsonstr::ftl ? BitOrder::FirstToLast : BitOrder::LastToFirst;
    });

    /* Create field class */
    if (type == jsonstr::fixedLenBitArray) {
        return createFixedLenBitArrayFc(jsonFc.loc(), align, len, byteOrder, bitOrder,
                                        std::move(attrs));
    } else if (type == jsonstr::fixedLenBitMap) {
        return createFixedLenBitMapFc(jsonFc.loc(), align, len, byteOrder,
                                      fixedLenBitMapFlagsOfJsonFixedLenBitMapFc(jsonFc), bitOrder,
                                      std::move(attrs));
    } else if (type == jsonstr::fixedLenBool) {
        return createFixedLenBoolFc(jsonFc.loc(), align, len, byteOrder, bitOrder,
                                    std::move(attrs));
    } else if (type == jsonstr::fixedLenUInt || type == jsonstr::fixedLenSInt) {
        return fcFromJsonFixedLenIntFc(jsonFc, type, align, len, byteOrder, bitOrder,
                                       std::move(attrs));
    } else {
        BT_ASSERT(type == jsonstr::fixedLenFloat);
        return createFixedLenFloatFc(jsonFc.loc(), align, len, byteOrder, bitOrder,
                                     std::move(attrs));
    }
}

/*
 * Creates and returns a variable-length integer field class from the
 * JSON variable-length integer field class value `jsonFc` and the
 * other parameters.
 */
Fc::UP fcFromJsonVarLenIntFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                             OptAttrs&& attrs)
{
    /* Preferred display base */
    const auto prefDispBase = prefDispBaseOfJsonIntFc(jsonFc);

    if (type == jsonstr::varLenUInt) {
        return createVarLenUIntFc(jsonFc.loc(), prefDispBase,
                                  intFcMappingsOfJsonIntFc<VarLenUIntFc>(jsonFc),
                                  uIntFieldRolesOfJsonUIntFc(jsonFc), std::move(attrs));
    } else {
        BT_ASSERT(type == jsonstr::varLenSInt);
        return createVarLenSIntFc(jsonFc.loc(), prefDispBase,
                                  intFcMappingsOfJsonIntFc<VarLenSIntFc>(jsonFc), std::move(attrs));
    }
}

/*
 * Creates and returns the field location of the JSON field class value
 * `jsonFc` from its `key` property.
 */
FieldLoc fieldLocOfJsonFc(const bt2c::JsonObjVal& jsonFc, const std::string& key)
{
    auto& jsonLoc = jsonFc[key]->asObj();

    /* Origin (scope) */
    const auto origin = bt2c::call([&jsonLoc]() -> bt2s::optional<Scope> {
        const auto jsonOrig = jsonLoc[jsonstr::origin];

        if (!jsonOrig) {
            return bt2s::nullopt;
        }

        auto& scopeName = *jsonOrig->asStr();

        if (scopeName == jsonstr::pktHeader) {
            return Scope::PktHeader;
        } else if (scopeName == jsonstr::pktCtx) {
            return Scope::PktCtx;
        } else if (scopeName == jsonstr::eventRecordHeader) {
            return Scope::EventRecordHeader;
        } else if (scopeName == jsonstr::eventRecordCommonCtx) {
            return Scope::CommonEventRecordCtx;
        } else if (scopeName == jsonstr::eventRecordSpecCtx) {
            return Scope::SpecEventRecordCtx;
        } else {
            BT_ASSERT(scopeName == jsonstr::eventRecordPayload);
            return Scope::EventRecordPayload;
        }
    });

    /* Path */
    FieldLoc::Items items;

    {
        auto& jsonPath = jsonLoc[jsonstr::path]->asArray();

        for (auto& jsonItem : jsonPath) {
            if (jsonItem->isNull()) {
                /* `null` becomes `bt2s::nullopt` */
                items.emplace_back(bt2s::nullopt);
            } else {
                items.push_back(*jsonItem->asStr());
            }
        }
    }

    /* Create field location */
    return createFieldLoc(jsonFc.loc(), origin, std::move(items));
}

/*
 * Creates and returns a string field class from the JSON string field
 * class value `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonStrFc(const bt2c::JsonObjVal& jsonFc, const std::string& type, OptAttrs&& attrs)
{
    const auto encoding = bt2c::call([&jsonFc] {
        const auto encodingStr = optStrOfObj(jsonFc, jsonstr::encoding);

        if (!encodingStr || encodingStr == jsonstr::utf8) {
            return StrEncoding::Utf8;
        } else if (encodingStr == jsonstr::utf16Be) {
            return StrEncoding::Utf16Be;
        } else if (encodingStr == jsonstr::utf16Le) {
            return StrEncoding::Utf16Le;
        } else if (encodingStr == jsonstr::utf32Be) {
            return StrEncoding::Utf32Be;
        } else {
            BT_ASSERT(encodingStr == jsonstr::utf32Le);
            return StrEncoding::Utf32Le;
        }
    });

    if (type == jsonstr::nullTerminatedStr) {
        return createNullTerminatedStrFc(jsonFc.loc(), encoding, std::move(attrs));
    } else if (type == jsonstr::staticLenStr) {
        return createStaticLenStrFc(jsonFc.loc(), lenOfJsonFc(jsonFc), encoding, std::move(attrs));
    } else {
        BT_ASSERT(type == jsonstr::dynLenStr);
        return createDynLenStrFc(jsonFc.loc(), fieldLocOfJsonFc(jsonFc, jsonstr::lenFieldLoc),
                                 encoding, std::move(attrs));
    }
}

/*
 * Creates and returns a static-length BLOB field class from the JSON
 * static-length BLOB field class value `jsonFc` and the other
 * parameters.
 */
Fc::UP fcFromJsonStaticLenBlobFc(const bt2c::JsonObjVal& jsonFc, const char * const mediaType,
                                 OptAttrs&& attrs)
{
    /* Has metadata stream UUID role? */
    const auto jsonRoles = jsonFc[jsonstr::roles];
    const auto hasMetadataStreamUuidRole = jsonRoles && jsonRoles->asArray().size() > 0;

    /* Create field class */
    return createStaticLenBlobFc(jsonFc.loc(), lenOfJsonFc(jsonFc), mediaType,
                                 hasMetadataStreamUuidRole, std::move(attrs));
}

/*
 * Creates and returns a BLOB field class from the JSON BLOB field class
 * value `jsonFc` and the other parameters.
 */
Fc::UP fcFromJsonBlobFc(const bt2c::JsonObjVal& jsonFc, const std::string& type, OptAttrs&& attrs)
{
    /* Media type */
    const auto mediaType = jsonFc.rawVal(jsonstr::mediaType, ir::defaultBlobMediaType);

    /* Create field class */
    if (type == jsonstr::staticLenBlob) {
        return fcFromJsonStaticLenBlobFc(jsonFc, mediaType, std::move(attrs));
    } else {
        BT_ASSERT(type == jsonstr::dynLenBlob);
        return createDynLenBlobFc(jsonFc.loc(), fieldLocOfJsonFc(jsonFc, jsonstr::lenFieldLoc),
                                  mediaType, std::move(attrs));
    }
}

/*
 * Returns the minimum alignment of the JSON field class value `jsonFc`.
 */
unsigned long long minAlignOfJsonFc(const bt2c::JsonObjVal& jsonFc) noexcept
{
    return jsonFc.rawVal(jsonstr::minAlign, 1ULL);
}

} /* namespace */

Ctf2FcBuilder::Ctf2FcBuilder(const bt2c::Logger& parentLogger) :
    _mLogger {parentLogger, "PLUGIN/CTF/CTF-2-FC-BUILDER"}
{
}

Fc::UP Ctf2FcBuilder::buildFcFromJsonVal(const bt2c::JsonVal& jsonFc) const
{
    if (jsonFc.isStr()) {
        /* Field class alias reference */
        return this->_aliasedFc(*jsonFc.asStr(), jsonFc.loc());
    }

    auto& jsonFcObj = jsonFc.asObj();

    /* Type */
    auto& type = jsonFcObj.rawStrVal(jsonstr::type);

    /* Attributes */
    auto attrs = attrsOfObj(jsonFcObj);

    /* Defer to specific method */
    if (type == jsonstr::fixedLenBitArray || type == jsonstr::fixedLenBitMap ||
        type == jsonstr::fixedLenBool || type == jsonstr::fixedLenUInt ||
        type == jsonstr::fixedLenSInt || type == jsonstr::fixedLenFloat) {
        return fcFromJsonFixedLenBitArrayFc(jsonFcObj, type, std::move(attrs));
    } else if (type == jsonstr::varLenUInt || type == jsonstr::varLenSInt) {
        return fcFromJsonVarLenIntFc(jsonFcObj, type, std::move(attrs));
    } else if (type == jsonstr::nullTerminatedStr || type == jsonstr::staticLenStr ||
               type == jsonstr::dynLenStr) {
        return fcFromJsonStrFc(jsonFcObj, type, std::move(attrs));
    } else if (type == jsonstr::staticLenBlob || type == jsonstr::dynLenBlob) {
        return fcFromJsonBlobFc(jsonFcObj, type, std::move(attrs));
    } else if (type == jsonstr::staticLenArray || type == jsonstr::dynLenArray) {
        return this->_fcFromJsonArrayFc(jsonFcObj, type, std::move(attrs));
    } else if (type == jsonstr::structure) {
        return this->_fcFromJsonStructFc(jsonFcObj, std::move(attrs));
    } else if (type == jsonstr::optional) {
        return this->_fcFromJsonOptionalFc(jsonFcObj, std::move(attrs));
    } else {
        BT_ASSERT(type == jsonstr::variant);
        return this->_fcFromJsonVariantFc(jsonFcObj, std::move(attrs));
    }
}

void Ctf2FcBuilder::addFcAlias(std::string name, Fc::UP fc, const bt2c::TextLoc& nameLoc)
{
    /* Check for duplicate */
    if (bt2c::contains(_mFcAliases, name)) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(bt2c::Error, nameLoc,
                                                   "Duplicate field class alias named `{}`.", name);
    }

    /* Add to map */
    _mFcAliases.emplace(std::move(name), std::move(fc));
}

Fc::UP Ctf2FcBuilder::_aliasedFc(const std::string& name, const bt2c::TextLoc& loc) const
{
    /* Check if the field class alias exists */
    const auto it = _mFcAliases.find(name);

    if (it == _mFcAliases.end()) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(bt2c::Error, loc,
                                                   "Cannot find field class alias `{}`.", name);
    }

    /* Return a clone of the field class alias */
    return it->second->clone();
}

Fc::UP Ctf2FcBuilder::_fcFromJsonArrayFc(const bt2c::JsonObjVal& jsonFc, const std::string& type,
                                         OptAttrs&& attrs) const
{
    /* Element field class */
    Fc::UP elemFc;

    try {
        elemFc = this->buildFcFromJsonVal(*jsonFc[jsonstr::elemFc]);
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(jsonFc.loc(), "Invalid array field class.");
    }

    /* Minimum alignment */
    const auto minAlign = minAlignOfJsonFc(jsonFc);

    /* Create field class */
    if (type == jsonstr::staticLenArray) {
        return createStaticLenArrayFc(jsonFc.loc(), lenOfJsonFc(jsonFc), std::move(elemFc),
                                      minAlign, false, std::move(attrs));
    } else {
        BT_ASSERT(type == jsonstr::dynLenArray);
        return createDynLenArrayFc(jsonFc.loc(), fieldLocOfJsonFc(jsonFc, jsonstr::lenFieldLoc),
                                   std::move(elemFc), minAlign, std::move(attrs));
    }
}

Fc::UP Ctf2FcBuilder::_fcFromJsonStructFc(const bt2c::JsonObjVal& jsonFc, OptAttrs&& attrs) const
{
    /* Minimum alignment */
    const auto minAlign = minAlignOfJsonFc(jsonFc);

    /* Member classes */
    StructFc::MemberClasses memberClasses;
    const auto jsonMemberClasses = jsonFc[jsonstr::memberClasses];

    try {
        if (jsonMemberClasses) {
            for (auto& jsonMemberCls : jsonMemberClasses->asArray()) {
                auto& jsonMemberClsObj = jsonMemberCls->asObj();
                auto& name = jsonMemberClsObj.rawStrVal(jsonstr::name);

                try {
                    memberClasses.emplace_back(createStructFieldMemberCls(
                        name, this->buildFcFromJsonVal(*jsonMemberClsObj[jsonstr::fc]),
                        attrsOfObj(jsonMemberClsObj)));
                } catch (const bt2c::Error&) {
                    BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                        jsonMemberClsObj.loc(), "Invalid structure field member class `{}`.", name);
                }
            }
        }
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(jsonFc.loc(),
                                                     "Invalid structure field class.");
    }

    /* Create field class */
    return createStructFc(jsonFc.loc(), std::move(memberClasses), minAlign, std::move(attrs));
}

Fc::UP Ctf2FcBuilder::_fcFromJsonOptionalFc(const bt2c::JsonObjVal& jsonFc, OptAttrs&& attrs) const
{
    try {
        /*
         * Create optional field class.
         *
         * The existence of the `selector-field-ranges` property
         * determines the expected field class type:
         *
         * Property exists:
         *     Class of optional fields with an integer selector.
         *
         * Property doesn't exist:
         *     Class of optional fields with a boolean selector.
         *
         * Note that we just trust the metadata at this point so there's
         * no validation: this can be done later with fcDepTypes().
         *
         * Also, if the optional field class has instances having an
         * integer selector, we can't know the signedness of such a
         * selector at this point. Therefore we enforce an unsigned
         * integer range set and will possibly cast to signed integer
         * ranges later once we know the selector signedness.
         */
        const auto jsonSelFieldRanges = jsonFc[jsonstr::selFieldRanges];
        auto fieldLoc = fieldLocOfJsonFc(jsonFc, jsonstr::selFieldLoc);
        auto fc = this->buildFcFromJsonVal(*jsonFc[jsonstr::fc]);

        if (jsonSelFieldRanges) {
            /* Expected integer selector */
            return createOptionalFc(jsonFc.loc(), std::move(fc), std::move(fieldLoc),
                                    intRangeSetFromJsonIntRangeSet<OptionalWithUIntSelFc::SelVal>(
                                        jsonSelFieldRanges->asArray()),
                                    std::move(attrs));
        } else {
            /* Expected boolean selector */
            return createOptionalFc(jsonFc.loc(), std::move(fc), std::move(fieldLoc),
                                    std::move(attrs));
        }
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(jsonFc.loc(), "Invalid optional field class.");
    }
}

Fc::UP Ctf2FcBuilder::_fcFromJsonVariantFc(const bt2c::JsonObjVal& jsonFc, OptAttrs&& attrs) const
{
    try {
        auto& jsonOpts = jsonFc[jsonstr::opts]->asArray();

        /*
         * We can't know the signedness of the selector at this point.
         * Therefore we enforce an unsigned integer range set and will
         * possibly cast to signed integer ranges later once we know the
         * selector signedness.
         */
        VariantWithUIntSelFc::Opts opts;

        for (auto it = jsonOpts.begin(); it != jsonOpts.end(); ++it) {
            auto& jsonOpt = (*it)->asObj();

            /* Create and append option */
            try {
                opts.emplace_back(
                    createVariantFcOpt(this->buildFcFromJsonVal(*jsonOpt[jsonstr::fc]),
                                       intRangeSetFromJsonIntRangeSet<VariantWithUIntSelFc::SelVal>(
                                           jsonOpt[jsonstr::selFieldRanges]->asArray()),
                                       optStrOfObj(jsonOpt, jsonstr::name), attrsOfObj(jsonOpt)));
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                    jsonFc.loc(), "Invalid variant field class option #{}.", it - jsonOpts.begin());
            }
        }

        /* Create field class */
        return createVariantFc(jsonFc.loc(), std::move(opts),
                               fieldLocOfJsonFc(jsonFc, jsonstr::selFieldLoc), std::move(attrs));
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(jsonFc.loc(), "Invalid variant field class.");
    }
}

} /* namespace src */
} /* namespace ctf */
