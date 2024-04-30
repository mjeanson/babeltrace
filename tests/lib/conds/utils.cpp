/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 */

#include <unordered_set>

#include <glib.h>
#include <string.h>

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "cpp-common/vendor/fmt/core.h"
#include "cpp-common/vendor/nlohmann/json.hpp"

#include "utils.hpp"

CondTrigger::CondTrigger(const Type type, const std::string& condId,
                         const bt2c::CStringView nameSuffix) noexcept :
    _mType {type},
    _mCondId {fmt::format("{}:{}", type == Type::Pre ? "pre" : "post", condId)},
    _mName {fmt::format("{}{}{}", condId, nameSuffix ? "-" : "", nameSuffix ? nameSuffix : "")}
{
}

SimpleCondTrigger::SimpleCondTrigger(std::function<void()> func, const Type type,
                                     const std::string& condId,
                                     const bt2c::CStringView nameSuffix) :
    CondTrigger {type, condId, nameSuffix},
    _mFunc {std::move(func)}
{
}

namespace {

void listCondTriggers(const CondTriggers& condTriggers) noexcept
{
    auto condTriggerArray = nlohmann::json::array();

    for (const auto& condTrigger : condTriggers) {
        condTriggerArray.push_back(nlohmann::json {
            {"cond-id", condTrigger->condId()},
            {"name", condTrigger->name()},
        });
    }

    fmt::println("{}", condTriggerArray.dump());
}

void checkNamesUnique(const CondTriggers& condTriggers)
{
    std::unordered_set<std::string> names;

    for (const auto& trigger : condTriggers) {
        const auto res = names.insert(trigger->name());

        if (!res.second) {
            fmt::println(stderr, "Duplicate test name `{}`", trigger->name());
            std::exit(1);
        }
    }
}

} /* namespace */

void condMain(const bt2s::span<const char * const> argv, const CondTriggers& condTriggers) noexcept
{
    BT_ASSERT(argv.size() >= 2);
    checkNamesUnique(condTriggers);

    if (strcmp(argv[1], "list") == 0) {
        listCondTriggers(condTriggers);
    } else if (strcmp(argv[1], "run") == 0) {
        /*
         * It's expected that calling the trigger below aborts (calls
         * bt_common_abort()). In this testing context, we don't want
         * any custom abortion command to run.
         */
        g_unsetenv("BABELTRACE_EXEC_ON_ABORT");

        /* Find the trigger */
        BT_ASSERT(argv.size() == 3);

        const auto name = argv[2];
        const auto it = std::find_if(condTriggers.begin(), condTriggers.end(),
                                     [&](const CondTrigger::UP& trigger) {
                                         return trigger->name() == name;
                                     });

        if (it == condTriggers.end()) {
            fmt::println(stderr, "No trigger named `{}` found.", name);
            std::exit(1);
        }

        /* Call the trigger */
        (**it)();
    }
}
