/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2018 Philippe Proulx <pproulx@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "cpp-common/bt2c/logging.hpp"

#include "ctf-meta-visitors.hpp"

static inline void warn_meaningless_field(const char *name, const char *scope_name,
                                          const bt2c::Logger& logger)
{
    BT_ASSERT(name);
    BT_CPPLOGW_SPEC(logger, "User field found in {}: ignoring: name=\"{}\"", scope_name, name);
}

static inline void warn_meaningless_fields(struct ctf_field_class *fc, const char *name,
                                           const char *scope_name, const bt2c::Logger& logger)
{
    uint64_t i;

    if (!fc) {
        goto end;
    }

    /*
     * 'name' is guaranteed to be non-NULL whenever the field class is not a
     * structure. In the case of a structure field class, its members' names
     * are used.
     */
    switch (fc->type) {
    case CTF_FIELD_CLASS_TYPE_FLOAT:
    case CTF_FIELD_CLASS_TYPE_STRING:
        warn_meaningless_field(name, scope_name, logger);
        break;
    case CTF_FIELD_CLASS_TYPE_INT:
    case CTF_FIELD_CLASS_TYPE_ENUM:
    {
        struct ctf_field_class_int *int_fc = ctf_field_class_as_int(fc);

        if (int_fc->meaning == CTF_FIELD_CLASS_MEANING_NONE && !int_fc->mapped_clock_class) {
            warn_meaningless_field(name, scope_name, logger);
        }

        break;
    }
    case CTF_FIELD_CLASS_TYPE_STRUCT:
    {
        struct ctf_field_class_struct *struct_fc = ctf_field_class_as_struct(fc);

        for (i = 0; i < struct_fc->members->len; i++) {
            struct ctf_named_field_class *named_fc =
                ctf_field_class_struct_borrow_member_by_index(struct_fc, i);

            warn_meaningless_fields(named_fc->fc, named_fc->name->str, scope_name, logger);
        }

        break;
    }
    case CTF_FIELD_CLASS_TYPE_VARIANT:
    {
        struct ctf_field_class_variant *var_fc = ctf_field_class_as_variant(fc);

        for (i = 0; i < var_fc->options->len; i++) {
            struct ctf_named_field_class *named_fc =
                ctf_field_class_variant_borrow_option_by_index(var_fc, i);

            warn_meaningless_fields(named_fc->fc, named_fc->name->str, scope_name, logger);
        }

        break;
    }
    case CTF_FIELD_CLASS_TYPE_ARRAY:
    {
        struct ctf_field_class_array *array_fc = ctf_field_class_as_array(fc);

        if (array_fc->meaning != CTF_FIELD_CLASS_MEANING_NONE) {
            goto end;
        }
    }
    /* fall-through */
    case CTF_FIELD_CLASS_TYPE_SEQUENCE:
    {
        struct ctf_field_class_array_base *array_fc = ctf_field_class_as_array_base(fc);

        warn_meaningless_fields(array_fc->elem_fc, name, scope_name, logger);
        break;
    }
    default:
        bt_common_abort();
    }

end:
    return;
}

void ctf_trace_class_warn_meaningless_header_fields(struct ctf_trace_class *ctf_tc,
                                                    const bt2c::Logger& parentLogger)
{
    uint64_t i;
    bt2c::Logger logger {parentLogger, "PLUGIN/CTF/META/WARN-MEANINGLESS-HEADER-FIELDS"};

    if (!ctf_tc->is_translated) {
        warn_meaningless_fields(ctf_tc->packet_header_fc, NULL, "packet header", logger);
    }

    for (i = 0; i < ctf_tc->stream_classes->len; i++) {
        ctf_stream_class *sc = (ctf_stream_class *) ctf_tc->stream_classes->pdata[i];

        if (!sc->is_translated) {
            warn_meaningless_fields(sc->event_header_fc, NULL, "event header", logger);
        }
    }
}
