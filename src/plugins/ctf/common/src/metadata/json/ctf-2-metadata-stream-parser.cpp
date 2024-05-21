/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <sstream>

#include "common/assert.h"
#include "cpp-common/bt2c/contains.hpp"
#include "cpp-common/bt2c/exc.hpp"
#include "cpp-common/bt2c/join.hpp"
#include "cpp-common/bt2c/json-val.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2c/make-span.hpp"
#include "cpp-common/bt2c/parse-json-as-val.hpp"
#include "cpp-common/bt2s/string-view.hpp"

#include "ctf-2-metadata-stream-parser.hpp"
#include "fcs-with-role.hpp"
#include "normalize-field-locs.hpp"
#include "plugins/ctf/common/src/metadata/ctf-ir.hpp"
#include "resolve-fcs-with-int-sel.hpp"
#include "strings.hpp"
#include "utils.hpp"
#include "validate-scope-fc-roles.hpp"

namespace ctf {
namespace src {

Ctf2MetadataStreamParser::Ctf2MetadataStreamParser(
    const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp, const ClkClsCfg& clkClsCfg,
    const bt2c::Logger& parentLogger) :
    MetadataStreamParser {selfComp, clkClsCfg},
    _mLogger {parentLogger, "PLUGIN/CTF/CTF-2-META-STREAM-PARSER"}, _mFragmentValReq {_mLogger},
    _mDefClkOffsetVal {bt2c::call([] {
        bt2c::JsonObjVal::Container entries;

        entries.insert(
            std::make_pair(jsonstr::seconds, bt2c::createJsonVal(0LL, bt2c::TextLoc {})));
        entries.insert(
            std::make_pair(jsonstr::cycles, bt2c::createJsonVal(0ULL, bt2c::TextLoc {})));
        return bt2c::createJsonVal(std::move(entries), bt2c::TextLoc {});
    })},
    _mFcBuilder {_mLogger}
{
}

MetadataStreamParser::ParseRet
Ctf2MetadataStreamParser::parse(const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                                const ClkClsCfg& clkClsCfg, const bt2c::ConstBytes buffer,
                                const bt2c::Logger& parentLogger)
{
    Ctf2MetadataStreamParser parser {selfComp, clkClsCfg, parentLogger};

    parser.parseSection(buffer);

    if (!parser.traceCls() || parser.traceCls()->dataStreamClasses().empty()) {
        /*
         * CTF 2 requires that a metadata stream contains at least one
         * data stream class fragment: `parser.traceCls()`, if it
         * exists, doesn't at this point and we know that `buffer`
         * contains the whole metadata stream.
         */
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(
            parser._mLogger, bt2::Error, "Missing data stream class fragment in metadata stream.");
    }

    return {parser.releaseTraceCls(), parser.metadataStreamUuid()};
}

void Ctf2MetadataStreamParser::_parseSection(const bt2c::ConstBytes buffer)
{
    this->_parseFragments(buffer);
}

void Ctf2MetadataStreamParser::_parseFragments(const bt2c::ConstBytes buffer)
{
    BT_ASSERT(buffer.data());

    auto fragmentBegin = buffer.begin();
    const auto curSectionOffsetInStream = _mCurOffsetInStream;

    while (true) {
        /* Find the beginning pointer of the current JSON fragment */
        while (fragmentBegin != buffer.end() && *fragmentBegin == 30) {
            /* Skip RS byte */
            ++fragmentBegin;
        }

        _mCurOffsetInStream =
            curSectionOffsetInStream + bt2c::DataLen::fromBytes(fragmentBegin - buffer.begin());

        if (fragmentBegin == buffer.end()) {
            /* We're done */
            return;
        }

        /* Find the end pointer of the current JSON fragment */
        auto fragmentEnd = fragmentBegin;

        while (fragmentEnd != buffer.end() && *fragmentEnd != 30) {
            /* Skip non-RS byte */
            ++fragmentEnd;
        }

        if (fragmentBegin == fragmentEnd) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, this->_loc(buffer, fragmentBegin), "Expecting a fragment.");
        }

        /* Parse one fragment */
        _mCurOffsetInStream =
            curSectionOffsetInStream + bt2c::DataLen::fromBytes(fragmentBegin - buffer.begin());
        this->_parseFragment(bt2c::makeSpan(fragmentBegin, fragmentEnd));

        /* Go to next fragment */
        fragmentBegin = fragmentEnd;
        ++_mCurFragmentIndex;
    }

    /* Adjust offset in metadata stream for the next section to parse */
    _mCurOffsetInStream = curSectionOffsetInStream + bt2c::DataLen::fromBytes(buffer.size());
}

void Ctf2MetadataStreamParser::_parseFragment(const bt2c::ConstBytes buffer)
{
    try {
        this->_handleFragment(*bt2c::parseJson(
            bt2s::string_view {reinterpret_cast<const char *>(buffer.data()), buffer.size()},
            _mCurOffsetInStream.bytes(), _mLogger));
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
            this->_loc(buffer, buffer.begin()), "Invalid fragment #{}.", _mCurFragmentIndex + 1);
    }
}

namespace {

/*
 * Returns the UUID of the JSON object value `jsonObjVal`, or
 * `bt2s::nullopt` if there's no such property.
 */
bt2s::optional<bt2c::Uuid> uuidOfObj(const bt2c::JsonObjVal& jsonObjVal)
{
    if (const auto jsonUuidVal = jsonObjVal[jsonstr::uuid]) {
        std::array<bt2c::Uuid::Val, bt2c::Uuid::size()> uuid;
        auto& jsonArrayUuidVal = jsonUuidVal->asArray();

        std::transform(jsonArrayUuidVal.begin(), jsonArrayUuidVal.end(), uuid.begin(),
                       [](const bt2c::JsonVal::UP& jsonUuidElemVal) {
                           return static_cast<bt2c::Uuid::Val>(*jsonUuidElemVal->asUInt());
                       });
        return bt2c::Uuid {uuid.data()};
    }

    return bt2s::nullopt;
}

} /* namespace */

void Ctf2MetadataStreamParser::_handleFragment(const bt2c::JsonVal& jsonFragment)
{
    /* Validate the fragment */
    _mFragmentValReq.validate(jsonFragment);

    /* Get type */
    auto& jsonFragmentObj = jsonFragment.asObj();
    auto& type = jsonFragmentObj.rawStrVal(jsonstr::type);

    /* Specific preamble fragment case */
    if (_mCurFragmentIndex == 0) {
        if (type != jsonstr::preamble) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(bt2c::Error, jsonFragmentObj.loc(),
                                                       "Expecting the preamble fragment.");
        }

        /* Possibly set the metadata stream UUID */
        _mMetadataStreamUuid = uuidOfObj(jsonFragmentObj);

        /*
         * Nothing more to do with the preamble fragment, but it
         * must exist!
         */
        return;
    }

    /* Defer to specific method */
    if (type == jsonstr::preamble) {
        BT_ASSERT(_mCurFragmentIndex > 0);
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
            bt2c::Error, jsonFragmentObj.loc(),
            "Preamble fragment must be the first fragment of the metadata stream.");
    } else if (type == jsonstr::fcAlias) {
        this->_handleFcAliasFragment(jsonFragmentObj);
    } else if (type == jsonstr::traceCls) {
        this->_handleTraceClsFragment(jsonFragmentObj);
    } else if (type == jsonstr::clkCls) {
        this->_handleClkClsFragment(jsonFragmentObj);
    } else if (type == jsonstr::dataStreamCls) {
        this->_handleDataStreamClsFragment(jsonFragmentObj);
    } else {
        BT_ASSERT(type == jsonstr::eventRecordCls);
        this->_handleEventRecordClsFragment(jsonFragmentObj);
    }
}

void Ctf2MetadataStreamParser::_handleFcAliasFragment(const bt2c::JsonObjVal& jsonFragment)
{
    auto& jsonNameVal = jsonFragment[jsonstr::name]->asStr();

    try {
        _mFcBuilder.addFcAlias(*jsonNameVal,
                               _mFcBuilder.buildFcFromJsonVal(*jsonFragment[jsonstr::fc]),
                               jsonNameVal.loc());
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(jsonFragment.loc(),
                                                     "Invalid field class alias fragment.");
    }
}

void Ctf2MetadataStreamParser::_validateScopeFcRoles(const Fc& fc,
                                                     const UIntFieldRoles& allowedRoles,
                                                     const bool allowMetadataStreamUuidRole)
{
    validateScopeFcRoles(fc, allowedRoles, allowMetadataStreamUuidRole, _mLogger);
}

void Ctf2MetadataStreamParser::_validatePktHeaderFcRoles(const Fc& pktHeaderFc)
{
    /* Validate allowed roles */
    this->_validateScopeFcRoles(pktHeaderFc,
                                {UIntFieldRole::PktMagicNumber, UIntFieldRole::DataStreamClsId,
                                 UIntFieldRole::DataStreamId},
                                true);

    /*
     * Validate that, if an unsigned integer field class FC has a
     * "packet magic number" role:
     *
     * • FC is a 32-bit fixed-length unsigned integer field class.
     *
     * • FC is the field class of the first member class of the packet
     *   header scope structure field class.
     *
     * • There's only one such field class within the whole packet
     *   header scope field class.
     */
    {
        const auto fcs = fcsWithRole(pktHeaderFc, {UIntFieldRole::PktMagicNumber}, false);

        if (fcs.size() > 1) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, (*fcs.begin())->loc(),
                "Packet header field class may contain zero or one field class having the role `{}`, not {}.",
                jsonstr::pktMagicNumber, fcs.size());
        }

        if (!fcs.empty()) {
            auto& magicFc = **fcs.begin();

            if (&pktHeaderFc.asStruct()[0].fc() != &magicFc) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, magicFc.loc(),
                    "A field class having the `{}` role must be the first class of the first member class "
                    "of the packet header field class.",
                    jsonstr::pktMagicNumber);
            }

            if (!magicFc.isFixedLenUInt()) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, magicFc.loc(),
                    "Unexpected type of field class having the `{}` role: "
                    "expecting `{}`.",
                    jsonstr::pktMagicNumber, jsonstr::fixedLenUInt);
            }

            auto& magicUIntFc = magicFc.asFixedLenUInt();

            if (*magicUIntFc.len() != 32) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, magicFc.loc(),
                    "Unexpected `{}` property of fixed-length unsigned integer field class having the `{}` role: "
                    "expecting 32, not {}.",
                    jsonstr::len, jsonstr::pktMagicNumber, *magicUIntFc.len());
            }
        }
    }

    /*
     * Validate that, if there's at least one static-length BLOB field
     * class having the "metadata stream UUID" role, then the metadata
     * stream has a UUID.
     */
    {
        const auto fcs = fcsWithRole(pktHeaderFc, {}, true);

        if (!fcs.empty() && !_mMetadataStreamUuid) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, (*fcs.begin())->loc(),
                "Static-length BLOB field class has the role `{}`, "
                "but the preamble fragment of the metadata stream has no `{}` property.",
                jsonstr::metadataStreamUuid, jsonstr::uuid);
        }
    }
}

namespace {

/*
 * A namespace, name, and UID tuple.
 */
struct NsNameUid final
{
    bt2s::optional<std::string> ns;
    bt2s::optional<std::string> name;
    bt2s::optional<std::string> uid;
};

/*
 * Returns the namespace, name, and UID of the JSON object `jsonObj`.
 */
NsNameUid nsNameUidOfObj(const bt2c::JsonObjVal& jsonObj)
{
    return NsNameUid {
        optStrOfObj(jsonObj, jsonstr::ns),
        optStrOfObj(jsonObj, jsonstr::name),
        optStrOfObj(jsonObj, jsonstr::uid),
    };
}

} /* namespace */

void Ctf2MetadataStreamParser::_handleTraceClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    /* Check for trace class uniqueness */
    if (_mTraceCls) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(bt2c::Error, jsonFragment.loc(),
                                                   "Duplicate trace class fragment.");
    }

    /* Namespace, name, and UID */
    auto nsNameUid = nsNameUidOfObj(jsonFragment);

    /* Create the packet header field class and validate it */
    auto pktHeaderFc =
        this->_scopeFcOfJsonVal(jsonFragment, jsonstr::pktHeaderFc, Scope::PktHeader);

    if (pktHeaderFc) {
        try {
            this->_validatePktHeaderFcRoles(*pktHeaderFc);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(pktHeaderFc->loc(),
                                                         "Invalid packet header field class.");
        }
    }

    /* Create the trace class */
    _mTraceCls = createTraceCls(std::move(nsNameUid.ns), std::move(nsNameUid.name),
                                std::move(nsNameUid.uid), bt2ValueOfObj(jsonFragment, jsonstr::env),
                                std::move(pktHeaderFc), attrsOfObj(jsonFragment));
}

void Ctf2MetadataStreamParser::_handleClkClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    /* ID */
    auto id = jsonFragment.rawStrVal(jsonstr::id);

    if (bt2c::contains(_mClkClasses, id)) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
            bt2c::Error, jsonFragment.loc(), "Duplicate clock class fragment with ID `{}`.", id);
    }

    /* Namespace, name, and UID */
    auto nsNameUid = nsNameUidOfObj(jsonFragment);

    /* Create corresponding clock class */
    auto clkCls = createClkCls(
        id, jsonFragment.rawUIntVal(jsonstr::freq), std::move(nsNameUid.ns),
        std::move(nsNameUid.name), std::move(nsNameUid.uid), bt2c::call([this, &jsonFragment] {
            auto& jsonOffsetVal = jsonFragment.val(jsonstr::offsetFromOrigin, *_mDefClkOffsetVal);

            return ClkOffset {
                bt2c::call([&jsonOffsetVal] {
                    if (const auto jsonOffsetSecsVal = jsonOffsetVal[jsonstr::seconds]) {
                        return rawIntValFromJsonIntVal<long long>(*jsonOffsetSecsVal);
                    }

                    return 0LL;
                }),
                jsonOffsetVal.rawVal(jsonstr::cycles, 0ULL),
            };
        }),
        bt2c::call([&jsonFragment]() -> bt2s::optional<ClkOrigin> {
            if (const auto jsonOriginVal = jsonFragment[jsonstr::origin]) {
                if (jsonOriginVal->isStr()) {
                    /* Unix epoch */
                    BT_ASSERT(*jsonOriginVal->asStr() == jsonstr::unixEpoch);
                    return ClkOrigin {};
                } else {
                    /* Custom */
                    auto& jsonOriginObjVal = jsonOriginVal->asObj();

                    /* Create clock origin */
                    auto nsNameUid = nsNameUidOfObj(jsonOriginObjVal);

                    BT_ASSERT(nsNameUid.name);
                    BT_ASSERT(nsNameUid.uid);
                    return ClkOrigin {std::move(nsNameUid.ns), std::move(*nsNameUid.name),
                                      std::move(*nsNameUid.uid)};
                }
            }

            return bt2s::nullopt;
        }),
        optStrOfObj(jsonFragment, jsonstr::descr),
        bt2c::call([&jsonFragment]() -> bt2s::optional<unsigned long long> {
            if (const auto jsonPrecision = jsonFragment[jsonstr::precision]) {
                return *jsonPrecision->asUInt();
            }

            return bt2s::nullopt;
        }),
        bt2c::call([&jsonFragment]() -> bt2s::optional<unsigned long long> {
            if (const auto jsonAccuracy = jsonFragment[jsonstr::accuracy]) {
                return *jsonAccuracy->asUInt();
            }

            return bt2s::nullopt;
        }),
        attrsOfObj(jsonFragment));

    /* Add to map of clock classes */
    _mClkClasses.emplace(std::make_pair(std::move(id), std::move(clkCls)));
}

namespace {

/*
 * Returns the "full class ID" string of `id`, `ns`, `name`, and `uid`.
 */
std::string fullClsIdStr(const unsigned long long id, const bt2s::optional<std::string>& ns,
                         const bt2s::optional<std::string>& name,
                         const bt2s::optional<std::string>& uid)
{
    std::ostringstream ss;

    ss << id;

    if (ns || name || uid) {
        std::vector<std::string> parts;

        if (ns) {
            parts.push_back(*ns);
        }

        if (name) {
            parts.push_back(*name);
        }

        if (uid) {
            parts.push_back(*uid);
        }

        ss << fmt::format(" ({})", bt2c::join(parts, "/"));
    }

    return ss.str();
}

/*
 * Returns the "full class ID" string of `id` and `nsNameUid`.
 */
std::string fullClsIdStr(const unsigned long long id, const NsNameUid& nsNameUid)
{
    return fullClsIdStr(id, nsNameUid.ns, nsNameUid.name, nsNameUid.uid);
}

/*
 * Returns the "full class ID" string of the class object `cls`.
 */
template <typename ClsT>
std::string fullClsIdStr(const ClsT& cls)
{
    return fullClsIdStr(cls.id(), cls.ns(), cls.name(), cls.uid());
}

} /* namespace */

void Ctf2MetadataStreamParser::_validateClkTsRoles(const Fc& fc, const bool allowClkTsRole)
{
    const auto fcs =
        fcsWithRole(fc, {UIntFieldRole::DefClkTs, UIntFieldRole::PktEndDefClkTs}, false);

    if (!fcs.empty() && !allowClkTsRole) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
            bt2c::Error, (*fcs.begin())->loc(),
            "Invalid unsigned integer field class having the `{}` or `{}` role because "
            "its containing data stream class fragment has no default clock class "
            "(missing `{}` property).",
            jsonstr::defClkTs, jsonstr::pktEndDefClkTs, jsonstr::defClkClsId);
    }
}

void Ctf2MetadataStreamParser::_validateDataStreamClsRoles(const Fc * const pktCtxFc,
                                                           const Fc * const eventRecordHeaderFc,
                                                           const Fc * const commonEventRecordCtxFc,
                                                           const bool allowClkTsRole)
{
    if (pktCtxFc) {
        try {
            this->_validateScopeFcRoles(*pktCtxFc,
                                        {UIntFieldRole::PktTotalLen, UIntFieldRole::PktContentLen,
                                         UIntFieldRole::DefClkTs, UIntFieldRole::PktEndDefClkTs,
                                         UIntFieldRole::DiscEventRecordCounterSnap,
                                         UIntFieldRole::PktSeqNum},
                                        false);
            this->_validateClkTsRoles(*pktCtxFc, allowClkTsRole);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(pktCtxFc->loc(),
                                                         "Invalid packet context field class.");
        }
    }

    if (eventRecordHeaderFc) {
        try {
            this->_validateScopeFcRoles(*eventRecordHeaderFc,
                                        {UIntFieldRole::DefClkTs, UIntFieldRole::EventRecordClsId},
                                        false);
            this->_validateClkTsRoles(*eventRecordHeaderFc, allowClkTsRole);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                eventRecordHeaderFc->loc(), "Invalid event record header field class.");
        }
    }

    if (commonEventRecordCtxFc) {
        try {
            /* No roles allowed */
            this->_validateScopeFcRoles(*commonEventRecordCtxFc, {}, false);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                commonEventRecordCtxFc->loc(), "Invalid common event record context field class.");
        }
    }
}

namespace {

/*
 * A string and text location pair.
 */
struct StrAndLoc final
{
    std::string str;
    bt2c::TextLoc loc;
};

/*
 * Returns the string value and text location of the property `propName`
 * within `jsonObjVal`, or `bt2s::nullopt` if there's no such property.
 */
bt2s::optional<StrAndLoc> optStrOfObjWithLoc(const bt2c::JsonObjVal& jsonObjVal,
                                             const std::string& propName)
{
    if (const auto jsonVal = jsonObjVal[propName]) {
        return StrAndLoc {*jsonVal->asStr(), jsonVal->loc()};
    }

    return bt2s::nullopt;
}

} /* namespace */

void Ctf2MetadataStreamParser::_handleDataStreamClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    this->_ensureExistingTraceCls();

    /* ID */
    const auto id = jsonFragment.rawVal(jsonstr::id, 0ULL);

    if ((*_mTraceCls)[id]) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
            bt2c::Error, jsonFragment.loc(),
            "Duplicate data stream class fragment with numeric ID {}.", id);
    }

    /* Default clock class */
    auto defClkCls = bt2c::call([this, &jsonFragment]() -> ClkCls::SP {
        if (const auto defClkClsId = optStrOfObjWithLoc(jsonFragment, jsonstr::defClkClsId)) {
            const auto it = _mClkClasses.find(defClkClsId->str);

            if (it == _mClkClasses.end()) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, defClkClsId->loc,
                    "`{}` doesn't identify an existing clock class fragment.", defClkClsId->str);
            }

            return it->second;
        }

        return {};
    });

    /* Namespace, name, and UID */
    const auto nsNameUid = nsNameUidOfObj(jsonFragment);

    /* Create data stream class */
    try {
        /* Create field classes */
        auto pktCtxFc =
            this->_dataStreamClsScopeFcOfJsonVal(jsonFragment, jsonstr::pktCtxFc, Scope::PktCtx);
        auto eventRecordHeaderFc = this->_dataStreamClsScopeFcOfJsonVal(
            jsonFragment, jsonstr::eventRecordHeaderFc, Scope::EventRecordHeader, pktCtxFc.get());
        auto commonEventRecordCtxFc = this->_dataStreamClsScopeFcOfJsonVal(
            jsonFragment, jsonstr::eventRecordCommonCtxFc, Scope::CommonEventRecordCtx,
            pktCtxFc.get(), eventRecordHeaderFc.get());

        /* Validate roles */
        this->_validateDataStreamClsRoles(pktCtxFc.get(), eventRecordHeaderFc.get(),
                                          commonEventRecordCtxFc.get(),
                                          static_cast<bool>(defClkCls));

        /* Create and add data stream class to current trace class */
        _mTraceCls->addDataStreamCls(createDataStreamCls(
            id, nsNameUid.ns, nsNameUid.name, nsNameUid.uid, std::move(pktCtxFc),
            std::move(eventRecordHeaderFc), std::move(commonEventRecordCtxFc), std::move(defClkCls),
            attrsOfObj(jsonFragment)));
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(jsonFragment.loc(),
                                                     "Invalid data stream class fragment {}.",
                                                     fullClsIdStr(id, nsNameUid));
    }
}

void Ctf2MetadataStreamParser::_validateEventRecordClsRoles(const Fc * const specCtxFc,
                                                            const Fc * const payloadFc)
{
    if (specCtxFc) {
        try {
            /* No roles allowed */
            this->_validateScopeFcRoles(*specCtxFc, {}, false);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(specCtxFc->loc(),
                                                         "Invalid specific context field class.");
        }
    }

    if (payloadFc) {
        try {
            /* No roles allowed */
            this->_validateScopeFcRoles(*payloadFc, {}, false);
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(payloadFc->loc(),
                                                         "Invalid payload field class.");
        }
    }
}

void Ctf2MetadataStreamParser::_handleEventRecordClsFragment(const bt2c::JsonObjVal& jsonFragment)
{
    this->_ensureExistingTraceCls();

    /* Data stream class ID */
    auto dataStreamCls = bt2c::call([this, &jsonFragment] {
        const auto jsonDataStreamClsIdVal = jsonFragment[jsonstr::dataStreamClsId];
        const auto dataStreamClsId =
            jsonDataStreamClsIdVal ? *jsonDataStreamClsIdVal->asUInt() : 0ULL;

        if (auto dataStreamCls = (*_mTraceCls)[dataStreamClsId]) {
            return dataStreamCls;
        }

        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            jsonDataStreamClsIdVal ? jsonDataStreamClsIdVal->loc() : jsonFragment.loc(),
            "No data stream class fragment exists with numeric ID {}.", dataStreamClsId);
    });

    /* ID */
    const auto id = bt2c::call([this, &jsonFragment, &dataStreamCls] {
        const auto jsonIdVal = jsonFragment[jsonstr::id];
        const auto id = jsonIdVal ? *jsonIdVal->asUInt() : 0ULL;

        if ((*dataStreamCls)[id]) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, jsonIdVal ? jsonIdVal->loc() : jsonFragment.loc(),
                "Duplicate event record class fragment with numeric ID {} within data stream class fragment {}.",
                id, fullClsIdStr(*dataStreamCls));
        }

        return id;
    });

    /* Create event record class */
    const auto nsNameUid = nsNameUidOfObj(jsonFragment);

    try {
        /* Create field classes */
        auto specCtxFc = this->_eventRecordClsScopeFcOfJsonVal(
            jsonFragment, jsonstr::specCtxFc, Scope::SpecEventRecordCtx, *dataStreamCls);
        auto payloadFc = this->_eventRecordClsScopeFcOfJsonVal(jsonFragment, jsonstr::payloadFc,
                                                               Scope::EventRecordPayload,
                                                               *dataStreamCls, specCtxFc.get());

        /* Validate roles */
        this->_validateEventRecordClsRoles(specCtxFc.get(), payloadFc.get());

        /* Create and add event record class to data stream class */
        dataStreamCls->addEventRecordCls(createEventRecordCls(
            id, nsNameUid.ns, nsNameUid.name, nsNameUid.uid, std::move(specCtxFc),
            std::move(payloadFc), attrsOfObj(jsonFragment)));
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
            jsonFragment.loc(),
            "Invalid event record class fragment {} (for data stream class fragment {}).",
            fullClsIdStr(id, nsNameUid), fullClsIdStr(*dataStreamCls));
    }
}

void Ctf2MetadataStreamParser::_ensureExistingTraceCls()
{
    if (_mTraceCls) {
        /* Already initialized */
        return;
    }

    /* Create a default CTF 2 trace class */
    _mTraceCls = createTraceCls();
}

Fc::UP Ctf2MetadataStreamParser::_scopeFcOfJsonVal(const bt2c::JsonObjVal& jsonVal,
                                                   const std::string& key, const Scope scope,
                                                   const Fc *pktHeaderFc, const Fc *pktCtxFc,
                                                   const Fc *eventRecordHeaderFc,
                                                   const Fc *commonEventRecordCtxFc,
                                                   const Fc *specEventRecordCtxFc,
                                                   const Fc *eventRecordPayloadFc)
{
    const auto jsonFcVal = jsonVal[key];

    if (!jsonFcVal) {
        /* Scope doesn't exist */
        return nullptr;
    }

    try {
        /* Build field class */
        auto fc = _mFcBuilder.buildFcFromJsonVal(*jsonFcVal);

        /* Make sure it's a structure field class */
        if (!fc->isStruct()) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(bt2c::Error, fc->loc(),
                                                       "Expecting a structure field class.");
        }

        /* Normalize field locations (relative → absolute) */
        normalizeFieldLocs(*fc, scope, _mLogger);

        /*
         * Resolve `OptionalWithUIntSel` and `VariantWithUIntSel`
         * field classes.
         */
        switch (scope) {
        case Scope::PktHeader:
            pktHeaderFc = fc.get();
            break;
        case Scope::PktCtx:
            pktCtxFc = fc.get();
            break;
        case Scope::EventRecordHeader:
            eventRecordHeaderFc = fc.get();
            break;
        case Scope::CommonEventRecordCtx:
            commonEventRecordCtxFc = fc.get();
            break;
        case Scope::SpecEventRecordCtx:
            specEventRecordCtxFc = fc.get();
            break;
        case Scope::EventRecordPayload:
            eventRecordPayloadFc = fc.get();
            break;
        default:
            bt_common_abort();
        }

        resolveFcsWithIntSel(*fc, scope, pktHeaderFc, pktCtxFc, eventRecordHeaderFc,
                             commonEventRecordCtxFc, specEventRecordCtxFc, eventRecordPayloadFc,
                             _mLogger);

        /* Done! */
        return fc;
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(jsonVal.loc(), "Invalid {} scope.",
                                                     scopeStr(scope));
    }
}

Fc::UP Ctf2MetadataStreamParser::_eventRecordClsScopeFcOfJsonVal(
    const bt2c::JsonObjVal& jsonEventRecordCls, const std::string& key, const Scope scope,
    const DataStreamCls& dataStreamCls, const Fc * const specEventRecordCtxFc,
    const Fc * const eventRecordPayloadFc)
{
    return this->_scopeFcOfJsonVal(jsonEventRecordCls, key, scope, _mTraceCls->pktHeaderFc(),
                                   dataStreamCls.pktCtxFc(), dataStreamCls.eventRecordHeaderFc(),
                                   dataStreamCls.commonEventRecordCtxFc(), specEventRecordCtxFc,
                                   eventRecordPayloadFc);
}

Fc::UP Ctf2MetadataStreamParser::_dataStreamClsScopeFcOfJsonVal(
    const bt2c::JsonObjVal& jsonDataStreamCls, const std::string& key, const Scope scope,
    const Fc * const pktCtxFc, const Fc * const eventRecordHeaderFc,
    const Fc * const commonEventRecordCtxFc)
{
    return this->_scopeFcOfJsonVal(jsonDataStreamCls, key, scope, _mTraceCls->pktHeaderFc(),
                                   pktCtxFc, eventRecordHeaderFc, commonEventRecordCtxFc);
}

} /* namespace src */
} /* namespace ctf */
