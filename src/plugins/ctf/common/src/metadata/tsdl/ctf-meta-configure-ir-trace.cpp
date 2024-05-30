/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Philippe Proulx <pproulx@efficios.com>
 */

#include <cstdint>

#include <babeltrace2/babeltrace.h>

#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2c/uuid.hpp"

#include "ctf-meta-configure-ir-trace.hpp"
#include "plugins/ctf/common/src/metadata/tsdl/ctf-meta.hpp"

void ctf_trace_class_configure_ir_trace(struct ctf_trace_class *tc, const bt2::Trace ir_trace)
{
    uint64_t i;

    BT_ASSERT(tc);

    if (tc->is_uuid_set) {
        ir_trace.uuid(bt2c::Uuid {tc->uuid});
    }

    for (i = 0; i < tc->env_entries->len; i++) {
        struct ctf_trace_class_env_entry *env_entry =
            ctf_trace_class_borrow_env_entry_by_index(tc, i);

        switch (env_entry->type) {
        case CTF_TRACE_CLASS_ENV_ENTRY_TYPE_INT:
            ir_trace.environmentEntry(env_entry->name->str, env_entry->value.i);
            break;
        case CTF_TRACE_CLASS_ENV_ENTRY_TYPE_STR:
            ir_trace.environmentEntry(env_entry->name->str, env_entry->value.str->str);
            break;
        default:
            bt_common_abort();
        }
    }
}

void ctf_trace_class_configure_ir_trace(const ctf::src::TraceCls& tc, bt2::Trace irTrace,
                                        const std::uint64_t mipVersion,
                                        const bt2c::Logger& parentLogger)
{
    bt2c::Logger logger {parentLogger, "PLUGIN/CTF/META/CONFIG-IR-TRACE"};

    if (tc.uid()) {
        if (mipVersion == 0) {
            /*
             * CTF 2 isn't supported under MIP 0, therefore we expect
             * `tc.uid()` to be a UUID string.
             */
            irTrace.uuid(bt2c::Uuid {*tc.uid()});
        } else {
            /* MIP ≥ 1: always a UID */
            irTrace.uid(*tc.uid());
        }
    }

    if (tc.env()) {
        tc.env()->forEach([&irTrace, &logger](const char *name, bt2::ConstValue val) {
            switch (val.type()) {
            case bt2::ValueType::SignedInteger:
                irTrace.environmentEntry(name, val.asSignedInteger().value());
                break;

            case bt2::ValueType::UnsignedInteger:
            {
                auto uval = val.asUnsignedInteger().value();

                if (uval > std::numeric_limits<std::int64_t>::max()) {
                    BT_CPPLOGW_SPEC(
                        logger,
                        "Cannot convert unsigned integer environment entry value to signed integer without overflowing. Skipping environment entry: "
                        "entry-name=\"{}\", entry-value={}",
                        name, uval);
                    break;
                }

                irTrace.environmentEntry(name, static_cast<std::int64_t>(uval));
                break;
            }

            case bt2::ValueType::String:
                irTrace.environmentEntry(name, val.asString().value().data());
                break;

            default:
                bt_common_abort();
            }
        });
    }
}
