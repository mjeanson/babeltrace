/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2024 Philippe Proulx <pproulx@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#include "common/common.h"
#include "compat/memstream.h"
#include "cpp-common/bt2c/aliases.hpp"

#include "ctf-1-metadata-stream-parser.hpp"
#include "plugins/ctf/common/src/metadata/ctf-ir.hpp"

namespace ctf {
namespace src {
namespace {

DispBase
dispBaseFromIrDispBase(const bt_field_class_integer_preferred_display_base dispBase) noexcept
{
    switch (dispBase) {
    case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_BINARY:
        return DispBase::Bin;
    case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_OCTAL:
        return DispBase::Oct;
    case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_DECIMAL:
        return DispBase::Dec;
    case BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL:
        return DispBase::Hex;
    default:
        bt_common_abort();
    }
}

ByteOrder byteOrderFromOrigByteOrder(const ctf_byte_order origByteOrder)
{
    switch (origByteOrder) {
    case CTF_BYTE_ORDER_LITTLE:
        return ByteOrder::Little;
    case CTF_BYTE_ORDER_BIG:
        return ByteOrder::Big;
    default:
        bt_common_abort();
    }
}

bt2s::optional<UIntFieldRole> roleFromOrigMeaning(const ctf_field_class_meaning meaning) noexcept
{
    switch (meaning) {
    case CTF_FIELD_CLASS_MEANING_PACKET_BEGINNING_TIME:
        return {UIntFieldRole::DefClkTs};
    case CTF_FIELD_CLASS_MEANING_PACKET_END_TIME:
        return {UIntFieldRole::PktEndDefClkTs};
    case CTF_FIELD_CLASS_MEANING_EVENT_CLASS_ID:
        return {UIntFieldRole::EventRecordClsId};
    case CTF_FIELD_CLASS_MEANING_STREAM_CLASS_ID:
        return {UIntFieldRole::DataStreamClsId};
    case CTF_FIELD_CLASS_MEANING_DATA_STREAM_ID:
        return {UIntFieldRole::DataStreamId};
    case CTF_FIELD_CLASS_MEANING_MAGIC:
        return {UIntFieldRole::PktMagicNumber};
    case CTF_FIELD_CLASS_MEANING_PACKET_COUNTER_SNAPSHOT:
        return {UIntFieldRole::PktSeqNum};
    case CTF_FIELD_CLASS_MEANING_DISC_EV_REC_COUNTER_SNAPSHOT:
        return {UIntFieldRole::DiscEventRecordCounterSnap};
    case CTF_FIELD_CLASS_MEANING_EXP_PACKET_TOTAL_SIZE:
        return {UIntFieldRole::PktTotalLen};
    case CTF_FIELD_CLASS_MEANING_EXP_PACKET_CONTENT_SIZE:
        return {UIntFieldRole::PktContentLen};
    case CTF_FIELD_CLASS_MEANING_UUID:
    case CTF_FIELD_CLASS_MEANING_NONE:
        return bt2s::nullopt;
    default:
        bt_common_abort();
    }
}

/*
 * Returns the integer field class roles which correspond to the meaning
 * of the original CTF IR integer field class `origIntFc`.
 */
UIntFieldRoles rolesFromOrigIntFc(const ctf_field_class_int& origIntFc)
{
    UIntFieldRoles roles;

    const auto role = roleFromOrigMeaning(origIntFc.meaning);

    if (role) {
        roles.insert(*role);
    }

    {
        const auto hasPktEndDefClkTsRole = role && *role == UIntFieldRole::PktEndDefClkTs;

        if (!hasPktEndDefClkTsRole && origIntFc.mapped_clock_class) {
            roles.insert(UIntFieldRole::DefClkTs);
        }
    }

    return roles;
}

/*
 * Translates the original CTF IR integer field class `origFc` and
 * returns the translated object.
 */
Fc::UP fcFromOrigFc(const ctf_field_class_int& oldFc)
{
    if (oldFc.is_signed) {
        return createFixedLenSIntFc(oldFc.base.base.alignment,
                                    bt2c::DataLen::fromBits(oldFc.base.size),
                                    byteOrderFromOrigByteOrder(oldFc.base.byte_order),
                                    bt2s::nullopt, dispBaseFromIrDispBase(oldFc.disp_base));
    } else {
        return createFixedLenUIntFc(
            oldFc.base.base.alignment, bt2c::DataLen::fromBits(oldFc.base.size),
            byteOrderFromOrigByteOrder(oldFc.base.byte_order), bt2s::nullopt,
            dispBaseFromIrDispBase(oldFc.disp_base), {}, rolesFromOrigIntFc(oldFc));
    }
}

/*
 * Translates the mappings of the original CTF IR enumeration field
 * class `origFc` and returns the translated objects.
 */
template <typename IntFcT>
static typename IntFcT::Mappings intFcMappingsFromOrigEnumFc(const ctf_field_class_enum& origFc)
{
    using Mappings = typename IntFcT::Mappings;
    using RangeSet = typename Mappings::mapped_type;

    Mappings mappings;

    for (std::size_t mappingIndex = 0; mappingIndex < origFc.mappings->len; ++mappingIndex) {
        auto& origMapping =
            *ctf_field_class_enum_borrow_mapping_by_index_const(&origFc, mappingIndex);

        typename RangeSet::Set ranges;

        for (std::size_t rangeIdx = 0; rangeIdx < origMapping.ranges->len; ++rangeIdx) {
            auto& origRange =
                *ctf_field_class_enum_mapping_borrow_range_by_index_const(&origMapping, rangeIdx);

            ranges.emplace(static_cast<typename IntFcT::Val>(origRange.lower.u),
                           static_cast<typename IntFcT::Val>(origRange.upper.u));
        }

        mappings.emplace(std::make_pair(origMapping.label->str, RangeSet {ranges}));
    }

    return mappings;
}

/*
 * Translates the original CTF IR enumeration field class `origFc` and
 * returns the translated object.
 */
Fc::UP fcFromOrigFc(const ctf_field_class_enum& origFc)
{
    const auto byteOrder = byteOrderFromOrigByteOrder(origFc.base.base.byte_order);
    const auto dispBase = dispBaseFromIrDispBase(origFc.base.disp_base);

    if (origFc.base.is_signed) {
        return createFixedLenSIntFc(origFc.base.base.base.alignment,
                                    bt2c::DataLen::fromBits(origFc.base.base.size), byteOrder,
                                    bt2s::nullopt, dispBase,
                                    intFcMappingsFromOrigEnumFc<FixedLenSIntFc>(origFc));
    } else {
        return createFixedLenUIntFc(
            origFc.base.base.base.alignment, bt2c::DataLen::fromBits(origFc.base.base.size),
            byteOrder, bt2s::nullopt, dispBase, intFcMappingsFromOrigEnumFc<FixedLenUIntFc>(origFc),
            rolesFromOrigIntFc(origFc.base));
    }
}

/*
 * Translates the original CTF IR floating-point number field class
 * `origFc` and returns the translated object.
 */
Fc::UP fcFromOrigFc(const ctf_field_class_float& origFc)
{
    return createFixedLenFloatFc(origFc.base.base.alignment,
                                 bt2c::DataLen::fromBits(origFc.base.size),
                                 byteOrderFromOrigByteOrder(origFc.base.byte_order));
}

/*
 * Returns the event record class log level name which corresponds to
 * the original CTF IR event record class log level `origLogLevel`.
 */
const char *eventRecordClsLogLevelNameFromOrigLogLevel(const bt_event_class_log_level origLogLevel)
{
    switch (origLogLevel) {
    case BT_EVENT_CLASS_LOG_LEVEL_EMERGENCY:
        return MetadataStreamParser::logLevelEmergencyName;
    case BT_EVENT_CLASS_LOG_LEVEL_ALERT:
        return MetadataStreamParser::logLevelAlertName;
    case BT_EVENT_CLASS_LOG_LEVEL_CRITICAL:
        return MetadataStreamParser::logLevelCriticalName;
    case BT_EVENT_CLASS_LOG_LEVEL_ERROR:
        return MetadataStreamParser::logLevelErrorName;
    case BT_EVENT_CLASS_LOG_LEVEL_WARNING:
        return MetadataStreamParser::logLevelWarningName;
    case BT_EVENT_CLASS_LOG_LEVEL_NOTICE:
        return MetadataStreamParser::logLevelNoticeName;
    case BT_EVENT_CLASS_LOG_LEVEL_INFO:
        return MetadataStreamParser::logLevelInfoName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_SYSTEM:
        return MetadataStreamParser::logLevelDebugSystemName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROGRAM:
        return MetadataStreamParser::logLevelDebugProgramName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_PROCESS:
        return MetadataStreamParser::logLevelDebugProcessName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_MODULE:
        return MetadataStreamParser::logLevelDebugModuleName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_UNIT:
        return MetadataStreamParser::logLevelDebugUnitName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_FUNCTION:
        return MetadataStreamParser::logLevelDebugFunctionName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG_LINE:
        return MetadataStreamParser::logLevelDebugLineName;
    case BT_EVENT_CLASS_LOG_LEVEL_DEBUG:
        return MetadataStreamParser::logLevelDebugName;
    default:
        bt_common_abort();
    }
}

/*
 * Returns the event record class attributes which correspond to the log
 * level and EMF URI properties of the original CTF IR event record
 * class `origEventRecordCls`.
 */
OptAttrs eventRecordClsBtAttrsFromOrigEventRecordCls(const ctf_event_class& origEventRecordCls)
{
    if (origEventRecordCls.emf_uri->len == 0 && !origEventRecordCls.is_log_level_set) {
        /* No log level and no EMF URI: no attributes */
        return OptAttrs {};
    }

    auto attrs = bt2::MapValue::create();
    auto nsMapVal = attrs->insertEmptyMap("babeltrace.org,2020");

    if (origEventRecordCls.emf_uri->len) {
        /* Set EMF URI attribute */
        nsMapVal.insert("emf-uri", origEventRecordCls.emf_uri->str);
    }

    if (origEventRecordCls.is_log_level_set) {
        /* Set log level attribute */
        nsMapVal.insert("log-level",
                        eventRecordClsLogLevelNameFromOrigLogLevel(origEventRecordCls.log_level));
    }

    return attrs;
}

/*
 * Translates the environment entries of the original CTF IR trace class
 * `origTraceCls` to a map value and returns it.
 */
bt2::ConstMapValue::Shared envMapValFromOrigTraceCls(const ctf_trace_class& origTraceCls)
{
    auto envMapVal = bt2::MapValue::create();

    for (std::size_t i = 0; i < origTraceCls.env_entries->len; ++i) {
        auto& origEnvEntry = *ctf_trace_class_borrow_env_entry_by_index(
            const_cast<ctf_trace_class *>(&origTraceCls), i);

        if (origEnvEntry.type == CTF_TRACE_CLASS_ENV_ENTRY_TYPE_INT) {
            envMapVal->insert(origEnvEntry.name->str, origEnvEntry.value.i);
        } else {
            BT_ASSERT(origEnvEntry.type == CTF_TRACE_CLASS_ENV_ENTRY_TYPE_STR);
            envMapVal->insert(origEnvEntry.name->str, origEnvEntry.value.str->str);
        }
    }

    return bt2::ConstMapValue::Shared::createWithoutRef(envMapVal.release().libObjPtr());
}

} /* namespace */

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_struct& origFc)
{
    StructFc::MemberClasses memberClasses;

    for (std::size_t i = 0; i < origFc.members->len; ++i) {
        auto& origMemberCls = *ctf_field_class_struct_borrow_member_by_index_const(&origFc, i);

        memberClasses.emplace_back(createStructFieldMemberCls(
            origMemberCls.name->str, this->_fcFromOrigFc(*origMemberCls.fc)));
    }

    return createStructFc(std::move(memberClasses), origFc.base.alignment);
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_array& origFc)
{
    if (origFc.base.is_text) {
        return createStaticLenStrFc(origFc.length);
    }

    return createStaticLenArrayFc(origFc.length, this->_fcFromOrigFc(*origFc.base.elem_fc),
                                  origFc.base.base.alignment,
                                  origFc.meaning == CTF_FIELD_CLASS_MEANING_UUID, OptAttrs {});
}

FieldLoc Ctf1MetadataStreamParser::_fieldLocFromOrigFieldPath(const ctf_field_path& origFieldPath)
{
    /* Get original CTF IR root field class and CTF IR scope */
    const auto origFcAndScope = bt2c::call([this, &origFieldPath] {
        switch (origFieldPath.root) {
        case CTF_SCOPE_PACKET_HEADER:
            return std::make_pair(_mFcTranslationCtx.origTraceCls->packet_header_fc,
                                  Scope::PktHeader);
        case CTF_SCOPE_PACKET_CONTEXT:
            return std::make_pair(_mFcTranslationCtx.origDataStreamCls->packet_context_fc,
                                  Scope::PktCtx);
        case CTF_SCOPE_EVENT_HEADER:
            return std::make_pair(_mFcTranslationCtx.origDataStreamCls->event_header_fc,
                                  Scope::EventRecordHeader);
        case CTF_SCOPE_EVENT_COMMON_CONTEXT:
            return std::make_pair(_mFcTranslationCtx.origDataStreamCls->event_common_context_fc,
                                  Scope::CommonEventRecordCtx);
        case CTF_SCOPE_EVENT_SPECIFIC_CONTEXT:
            return std::make_pair(_mFcTranslationCtx.origEventRecordCls->spec_context_fc,
                                  Scope::SpecEventRecordCtx);
        case CTF_SCOPE_EVENT_PAYLOAD:
            return std::make_pair(_mFcTranslationCtx.origEventRecordCls->payload_fc,
                                  Scope::EventRecordPayload);
        default:
            bt_common_abort();
        }
    });

    /* Translate field path to field scope */
    FieldLoc::Items items;
    auto origFc = origFcAndScope.first;

    for (std::size_t i = 0; i < origFieldPath.path->len; ++i) {
        switch (origFc->type) {
        case CTF_FIELD_CLASS_TYPE_SEQUENCE:
        case CTF_FIELD_CLASS_TYPE_ARRAY:
        {
            BT_ASSERT(ctf_field_path_borrow_index_by_index(&origFieldPath, i) == -1);
            origFc = ctf_field_class_as_array_base(origFc)->elem_fc;
            break;
        }
        case CTF_FIELD_CLASS_TYPE_STRUCT:
        {
            const auto origChildFc = ctf_field_class_compound_borrow_named_field_class_by_index(
                origFc, ctf_field_path_borrow_index_by_index(&origFieldPath, i));

            BT_ASSERT(origChildFc);
            items.emplace_back(origChildFc->name->str);
            origFc = origChildFc->fc;
            break;
        }
        case CTF_FIELD_CLASS_TYPE_VARIANT:
        {
            const auto origChildFc = ctf_field_class_compound_borrow_named_field_class_by_index(
                origFc, ctf_field_path_borrow_index_by_index(&origFieldPath, i));

            BT_ASSERT_DBG(origChildFc);

            /*
             * Variant field class option names aren't part of a CTF IR
             * field location: like for the current element of an array
             * field, a dependency which is part of a variant field F is
             * always within the current option of F.
             */
            origFc = origChildFc->fc;
            break;
        }
        default:
            break;
        }
    }

    return createFieldLoc(origFcAndScope.second, std::move(items));
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_sequence& origFc)
{
    auto lenFieldLoc = this->_fieldLocFromOrigFieldPath(origFc.length_path);

    if (origFc.base.is_text) {
        return createDynLenStrFc(std::move(lenFieldLoc));
    }

    return createDynLenArrayFc(std::move(lenFieldLoc), this->_fcFromOrigFc(*origFc.base.elem_fc));
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class_variant& origFc)
{
    auto selFieldLoc = this->_fieldLocFromOrigFieldPath(origFc.tag_path);

    if (origFc.tag_fc->base.is_signed) {
        return createVariantFc(this->_variantOptsFromOrigVariantFc<VariantWithSIntSelFc>(origFc),
                               std::move(selFieldLoc));
    } else {
        return createVariantFc(this->_variantOptsFromOrigVariantFc<VariantWithUIntSelFc>(origFc),
                               std::move(selFieldLoc));
    }
}

Fc::UP Ctf1MetadataStreamParser::_fcFromOrigFc(const ctf_field_class& origFc)
{
    /*
     * The ctf_field_class_as_*() functions only accept non-const
     * pointers.
     */
    auto& nonConstOrigFc = const_cast<ctf_field_class&>(origFc);

    switch (origFc.type) {
    case CTF_FIELD_CLASS_TYPE_INT:
        return fcFromOrigFc(*ctf_field_class_as_int(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_ENUM:
        return fcFromOrigFc(*ctf_field_class_as_enum(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_FLOAT:
        return fcFromOrigFc(*ctf_field_class_as_float(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_STRING:
        return createNullTerminatedStrFc();
    case CTF_FIELD_CLASS_TYPE_STRUCT:
        return this->_fcFromOrigFc(*ctf_field_class_as_struct(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_ARRAY:
        return this->_fcFromOrigFc(*ctf_field_class_as_array(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
        return this->_fcFromOrigFc(*ctf_field_class_as_sequence(&nonConstOrigFc));
    case CTF_FIELD_CLASS_TYPE_VARIANT:
        return this->_fcFromOrigFc(*ctf_field_class_as_variant(&nonConstOrigFc));
    default:
        bt_common_abort();
    }
}

bt2c::FileUP Ctf1MetadataStreamParser::_fileUpFromStr(const std::string& str)
{
    if (const auto fp = bt_fmemopen(const_cast<char *>(str.data()), str.size(), "rb")) {
        return bt2c::FileUP {fp};
    }

    BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "bt_fmemopen() failed.");
}

void Ctf1MetadataStreamParser::_parseSection(const bt2c::ConstBytes buffer)
{
    {
        const auto metadataStr = _mStreamDecoder.decode(buffer);
        const auto plaintextFile = this->_fileUpFromStr(metadataStr);

        /* Append the metadata text content to the TSDL scanner */
        if (const auto ret = ctf_scanner_append_ast(_mScanner.get(), plaintextFile.get())) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error, "Cannot create the metadata stream AST from TSDL text: ret={}", ret);
        }
    }

    /* Make some basic AST node validation */
    if (const auto ret = ctf_visitor_semantic_check(0, &_mScanner.get()->ast->root, _mLogger)) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error, "Failed to validate metadata stream AST nodes: ret={}", ret);
    }

    /* Convert AST nodes to original CTF IR objects */
    {
        const auto ret = ctf_visitor_generate_ir_visit_node(_mOrigCtfIrGenerator.get(),
                                                            &_mScanner.get()->ast->root);

        switch (ret) {
        case 0:
            /* Success */
            break;
        case -EINCOMPLETE:
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "Incomplete metadata stream section.");
        default:
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
                bt2c::Error,
                "Failed to create original CTF IR objects from metadata stream AST nodes: ret={}",
                ret);
        }
    }

    /* Translate original CTF IR objects to current CTF IR ones */
    this->_tryTranslate(*_mOrigCtfIrGenerator->ctf_tc);
}

void Ctf1MetadataStreamParser::_tryTranslate(ctf_trace_class& origTraceCls)
{
    _mFcTranslationCtx.origTraceCls = &origTraceCls;

    if (!_mTraceCls) {
        /* No trace class yet: translate original CTF IR trace class */
        _mTraceCls = this->_translateTraceCls(origTraceCls);
    }

    /* Try to translate data stream classes and event record classes */
    for (std::size_t iDataStreamCls = 0; iDataStreamCls < origTraceCls.stream_classes->len;
         ++iDataStreamCls) {
        auto& origDataStreamCls =
            *static_cast<ctf_stream_class *>(origTraceCls.stream_classes->pdata[iDataStreamCls]);

        _mFcTranslationCtx.origDataStreamCls = &origDataStreamCls;
        _mFcTranslationCtx.origEventRecordCls = nullptr;
        _mFcTranslationCtx.dataStreamCls = &this->_tryTranslateDataStreamCls(origDataStreamCls);

        for (std::size_t iEventRecordCls = 0;
             iEventRecordCls < origDataStreamCls.event_classes->len; iEventRecordCls++) {
            auto& origEventRecordCls = *static_cast<ctf_event_class *>(
                origDataStreamCls.event_classes->pdata[iEventRecordCls]);

            _mFcTranslationCtx.origEventRecordCls = &origEventRecordCls;
            this->_tryTranslateEventRecordCls(origEventRecordCls);
        }
    }
}

std::unique_ptr<TraceCls>
Ctf1MetadataStreamParser::_translateTraceCls(ctf_trace_class& origTraceCls)
{
    BT_ASSERT(!origTraceCls.is_translated);

    /* Translate packet header field class */
    Fc::UP pktHeaderFc;

    if (origTraceCls.packet_header_fc) {
        pktHeaderFc = this->_fcFromOrigFc(*origTraceCls.packet_header_fc);
    }

    /* UID */
    bt2s::optional<std::string> uid;

    if (origTraceCls.is_uuid_set) {
        uid = bt2c::UuidView {origTraceCls.uuid}.str();

        /*
         * For CTF 1, the trace class UUID is also the metadata
         * stream UUID.
         */
        _mMetadataStreamUuid = origTraceCls.uuid;
    }

    /* Create trace class */
    auto traceCls = createTraceCls(bt2s::nullopt, bt2s::nullopt, std::move(uid),
                                   envMapValFromOrigTraceCls(origTraceCls), std::move(pktHeaderFc));

    /* Mark original CTF IR trace class as translated */
    origTraceCls.is_translated = true;

    /* Return created trace class */
    return traceCls;
}

ClkCls::SP Ctf1MetadataStreamParser::_clkClsFromOrigClkCls(const ctf_clock_class& origClkCls)
{
    /* Try to find a corresponding clock class for `origClkCls`*/
    const auto it = _mClkClsMap.find(&origClkCls);

    if (it != _mClkClsMap.end()) {
        /* Found it */
        return it->second;
    }

    /* Translate clock class */
    {
        /* Description */
        bt2s::optional<std::string> descr;

        if (origClkCls.description->len > 0) {
            descr = origClkCls.description->str;
        }

        /* UID from UUID */
        bt2s::optional<std::string> uid;

        if (origClkCls.has_uuid) {
            uid = bt2c::UuidView {origClkCls.uuid}.str();
        }

        /* Clock origin */
        bt2s::optional<ClkOrigin> origin;

        if (origClkCls.is_absolute) {
            /* Unix epoch */
            origin = ClkOrigin {};
        }

        /* Create clock class */
        auto clkCls = createClkCls(origClkCls.name->str, origClkCls.frequency, bt2s::nullopt,
                                   origClkCls.name->str, std::move(uid),
                                   ClkOffset {origClkCls.offset_seconds, origClkCls.offset_cycles},
                                   std::move(origin), std::move(descr), origClkCls.precision);

        /* Add to map of translated clock classes */
        _mClkClsMap.emplace(&origClkCls, clkCls);

        /* Return created clock class */
        return clkCls;
    }
}

DataStreamCls&
Ctf1MetadataStreamParser::_tryTranslateDataStreamCls(ctf_stream_class& origDataStreamCls)
{
    if (origDataStreamCls.is_translated) {
        /* Already translated: return it */
        return *(*_mTraceCls)[origDataStreamCls.id];
    }

    /* Translate packet context field class */
    Fc::UP pktCtxFc;

    if (origDataStreamCls.packet_context_fc) {
        pktCtxFc = this->_fcFromOrigFc(*origDataStreamCls.packet_context_fc);
    }

    /* Translate event record header field class */
    Fc::UP eventRecordHeaderFc;

    if (origDataStreamCls.event_header_fc) {
        eventRecordHeaderFc = this->_fcFromOrigFc(*origDataStreamCls.event_header_fc);
    }

    /* Translate common event record context field class */
    Fc::UP commonEventRecordCtxFc;

    if (origDataStreamCls.event_common_context_fc) {
        commonEventRecordCtxFc = this->_fcFromOrigFc(*origDataStreamCls.event_common_context_fc);
    }

    /* Translate default clock class */
    ClkCls::SP defClkCls;

    if (origDataStreamCls.default_clock_class) {
        defClkCls = this->_clkClsFromOrigClkCls(*origDataStreamCls.default_clock_class);
    }

    /* Create data stream class */
    auto dataStreamClsSp = createDataStreamCls(
        origDataStreamCls.id, bt2s::nullopt, bt2s::nullopt, bt2s::nullopt, std::move(pktCtxFc),
        std::move(eventRecordHeaderFc), std::move(commonEventRecordCtxFc), std::move(defClkCls));
    auto& dataStreamCls = *dataStreamClsSp;

    /* Add to trace class */
    _mTraceCls->addDataStreamCls(std::move(dataStreamClsSp));

    /* Mark original CTF IR data stream class as translated */
    origDataStreamCls.is_translated = true;

    /* Return created data stream class */
    return dataStreamCls;
}

void Ctf1MetadataStreamParser::_tryTranslateEventRecordCls(ctf_event_class& origEventRecordCls)
{
    if (origEventRecordCls.is_translated) {
        /* Already translated */
        return;
    }

    /* Translate specific context field class, if any */
    Fc::UP specCtxFc;

    if (origEventRecordCls.spec_context_fc) {
        specCtxFc = this->_fcFromOrigFc(*origEventRecordCls.spec_context_fc);
    }

    /* Translate payload field class, if any */
    Fc::UP payloadFc;

    if (origEventRecordCls.payload_fc) {
        payloadFc = this->_fcFromOrigFc(*origEventRecordCls.payload_fc);
    }

    /* Create event record class */
    auto eventRecordCls =
        createEventRecordCls(origEventRecordCls.id, bt2s::nullopt, origEventRecordCls.name->str,
                             bt2s::nullopt, std::move(specCtxFc), std::move(payloadFc),
                             eventRecordClsBtAttrsFromOrigEventRecordCls(origEventRecordCls));

    /* Add to data stream class */
    BT_ASSERT(_mFcTranslationCtx.dataStreamCls);
    _mFcTranslationCtx.dataStreamCls->addEventRecordCls(std::move(eventRecordCls));

    /* Mark original CTF IR event record class as translated */
    origEventRecordCls.is_translated = true;
}

Ctf1MetadataStreamParser::Ctf1MetadataStreamParser(
    const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp, const ClkClsCfg& clkClsCfg,
    const bt2c::Logger& parentLogger) :
    MetadataStreamParser {selfComp, clkClsCfg},
    _mLogger {parentLogger, "PLUGIN/CTF/CTF-1-META-STREAM-PARSER"},
    _mOrigCtfIrGenerator {ctf_visitor_generate_ir_create({}, _mLogger)},
    _mScanner {ctf_scanner_alloc(_mLogger)}, _mStreamDecoder {_mLogger}
{
}

MetadataStreamParser::ParseRet
Ctf1MetadataStreamParser::parse(const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                                const ClkClsCfg& clkClsCfg, const bt2c::ConstBytes buffer,
                                const bt2c::Logger& parentLogger)
{
    Ctf1MetadataStreamParser parser {selfComp, clkClsCfg, parentLogger};

    parser.parseSection(buffer);
    return {parser.releaseTraceCls(), parser.metadataStreamUuid()};
}

} /* namespace src */
} /* namespace ctf */
