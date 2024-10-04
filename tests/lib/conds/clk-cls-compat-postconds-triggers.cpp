/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024 EfficiOS Inc.
 */

#include "cpp-common/bt2s/make-unique.hpp"
#include "cpp-common/vendor/fmt/format.h" /* IWYU pragma: keep */

#include "../utils/run-in.hpp"
#include "clk-cls-compat-postconds-triggers.hpp"
#include "common.hpp"

namespace {

/*
 * `RunIn` implementation to trigger clock (in)compatibility postcondition
 * assertions.
 */
class ClockClsCompatRunIn final : public RunIn
{
public:
    enum class MsgType
    {
        StreamBeg,
        MsgIterInactivity,
    };

    using CreateClockCls = std::function<bt2::ClockClass::Shared(bt2::SelfComponent)>;

    explicit ClockClsCompatRunIn(const MsgType msgType1, CreateClockCls createClockCls1,
                                 const MsgType msgType2, CreateClockCls createClockCls2) noexcept :
        _mMsgType1 {msgType1},
        _mMsgType2 {msgType2}, _mCreateClockCls1 {std::move(createClockCls1)},
        _mCreateClockCls2 {std::move(createClockCls2)}
    {
    }

    void onMsgIterNext(bt2::SelfMessageIterator self, bt2::ConstMessageArray& msgs) override
    {
        /* In case the expected assertion doesn't trigger, avoid looping indefinitely. */
        BT_ASSERT(!_mBeenThere);

        const auto traceCls = self.component().createTraceClass();
        const auto trace = traceCls->instantiate();

        msgs.append(this->_createOneMsg(self, _mMsgType1, _mCreateClockCls1, *trace));
        msgs.append(this->_createOneMsg(self, _mMsgType2, _mCreateClockCls2, *trace));
        _mBeenThere = true;
    }

private:
    static bt2::Message::Shared _createOneMsg(const bt2::SelfMessageIterator self,
                                              const MsgType msgType,
                                              const CreateClockCls& createClockCls,
                                              const bt2::Trace trace)
    {
        const auto clockCls =
            createClockCls ? createClockCls(self.component()) : bt2::ClockClass::Shared {};

        switch (msgType) {
        case MsgType::StreamBeg:
        {
            const auto streamCls = trace.cls().createStreamClass();

            if (clockCls) {
                streamCls->defaultClockClass(*clockCls);
            }

            return self.createStreamBeginningMessage(*streamCls->instantiate(trace));
        }

        case MsgType::MsgIterInactivity:
            BT_ASSERT(clockCls);
            return self.createMessageIteratorInactivityMessage(*clockCls, 12);
        };

        bt_common_abort();
    }

    MsgType _mMsgType1, _mMsgType2;
    CreateClockCls _mCreateClockCls1, _mCreateClockCls2;
    bool _mBeenThere = false;
};

__attribute__((used)) const char *format_as(const ClockClsCompatRunIn::MsgType msgType)
{
    switch (msgType) {
    case ClockClsCompatRunIn::MsgType::StreamBeg:
        return "sb";

    case ClockClsCompatRunIn::MsgType::MsgIterInactivity:
        return "mii";
    }

    bt_common_abort();
}

const bt2c::Uuid uuidA {"f00aaf65-ebec-4eeb-85b2-fc255cf1aa8a"};
const bt2c::Uuid uuidB {"03482981-a77b-4d7b-94c4-592bf9e91785"};
constexpr const char *nsA = "namespace-a";
constexpr const char *nameA = "name-a";
constexpr const char *uidA = "uid-a";
constexpr const char *nsB = "namespace-b";
constexpr const char *nameB = "name-b";
constexpr const char *uidB = "uid-b";

} /* namespace */

/*
 * Add clock class compatibility postcondition failures triggers.
 *
 * Each trigger below makes a message iterator return two messages with
 * incompatible clock classes, leading to a postcondition failure.
 */
void addClkClsCompatTriggers(CondTriggers& triggers)
{
    const auto addValidCases = [&triggers](
                                   const ClockClsCompatRunIn::CreateClockCls& createClockCls1,
                                   const ClockClsCompatRunIn::CreateClockCls& createClockCls2,
                                   const char * const condId, std::uint64_t graphMipVersion) {
        /*
         * Add triggers for all possible combinations of message types.
         *
         * It's not possible to create message iterator inactivity messages
         * without a clock class.
         */
        static constexpr std::array<ClockClsCompatRunIn::MsgType, 2> msgTypes {
            ClockClsCompatRunIn::MsgType::StreamBeg,
            ClockClsCompatRunIn::MsgType::MsgIterInactivity,
        };

        const auto isInvalidCase = [](const ClockClsCompatRunIn::MsgType msgType,
                                      const ClockClsCompatRunIn::CreateClockCls& createClockCls) {
            return msgType == ClockClsCompatRunIn::MsgType::MsgIterInactivity && !createClockCls;
        };

        for (const auto msgType1 : msgTypes) {
            if (isInvalidCase(msgType1, createClockCls1)) {
                continue;
            }

            for (const auto msgType2 : msgTypes) {
                if (isInvalidCase(msgType2, createClockCls2)) {
                    continue;
                }

                triggers.emplace_back(bt2s::make_unique<RunInCondTrigger<ClockClsCompatRunIn>>(
                    ClockClsCompatRunIn {msgType1, createClockCls1, msgType2, createClockCls2},
                    CondTrigger::Type::Post, condId, graphMipVersion,
                    fmt::format("mip{}-{}-{}", graphMipVersion, msgType1, msgType2)));
            }
        }
    };

    forEachMipVersion([&](const std::uint64_t graphMipVersion) {
        addValidCases(
            {},
            [](const bt2::SelfComponent self) {
                return self.createClockClass();
            },
            "message-iterator-class-next-method:stream-class-has-no-clock-class", graphMipVersion);

        if (graphMipVersion == 0) {
            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(true);
                    return clockCls;
                },
                {},
                "message-iterator-class-next-method:stream-class-has-clock-class-with-unix-epoch-origin",
                graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(true);
                    return clockCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(false);
                    return clockCls;
                },
                "message-iterator-class-next-method:clock-class-has-unix-epoch-origin",
                graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(false).uuid(uuidA);
                    return clockCls;
                },
                {}, "message-iterator-class-next-method:stream-class-has-clock-class-with-uuid",
                graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(false).uuid(uuidA);
                    return clockCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(true);
                    return clockCls;
                },
                "message-iterator-class-next-method:clock-class-has-unknown-origin",
                graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clkCls = self.createClockClass();

                    clkCls->originIsUnixEpoch(false).uuid(uuidA);
                    return clkCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(false);
                    return clockCls;
                },
                "message-iterator-class-next-method:clock-class-has-uuid", graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clkCls = self.createClockClass();

                    clkCls->originIsUnixEpoch(false).uuid(uuidA);
                    return clkCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clkCls = self.createClockClass();

                    clkCls->originIsUnixEpoch(false).uuid(uuidB);
                    return clkCls;
                },
                "message-iterator-class-next-method:clock-class-has-expected-uuid",
                graphMipVersion);
        } else {
            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(true);
                    return clockCls;
                },
                {},
                "message-iterator-class-next-method:stream-class-has-clock-class-with-known-origin",
                graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(true);
                    return clockCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(false);
                    return clockCls;
                },
                "message-iterator-class-next-method:clock-class-has-known-origin", graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(false).nameSpace("ze-ns").name("ze-name").uid(
                        "ze-uid");
                    return clockCls;
                },
                {}, "message-iterator-class-next-method:stream-class-has-clock-class-with-id",
                graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(false).nameSpace("ze-ns").name("ze-name").uid(
                        "ze-uid");
                    return clockCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clockCls = self.createClockClass();

                    clockCls->originIsUnixEpoch(true);
                    return clockCls;
                },
                "message-iterator-class-next-method:clock-class-has-unknown-origin",
                graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clkCls = self.createClockClass();

                    clkCls->originIsUnixEpoch(false).nameSpace(nsA).name(nameA).uid(uidA);
                    return clkCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clkCls = self.createClockClass();

                    clkCls->originIsUnixEpoch(false);
                    return clkCls;
                },
                "message-iterator-class-next-method:clock-class-has-id", graphMipVersion);

            addValidCases(
                [](const bt2::SelfComponent self) {
                    const auto clkCls = self.createClockClass();

                    clkCls->originIsUnixEpoch(false).nameSpace(nsA).name(nameA).uid(uidA);
                    return clkCls;
                },
                [](const bt2::SelfComponent self) {
                    const auto clkCls = self.createClockClass();

                    clkCls->originIsUnixEpoch(false).nameSpace(nsB).name(nameB).uid(uidB);
                    return clkCls;
                },
                "message-iterator-class-next-method:clock-class-has-expected-id", graphMipVersion);
        }

        addValidCases(
            [](const bt2::SelfComponent self) {
                const auto clkCls = self.createClockClass();

                clkCls->originIsUnixEpoch(false);
                return clkCls;
            },
            {}, "message-iterator-class-next-method:stream-class-has-clock-class", graphMipVersion);

        addValidCases(
            [](const bt2::SelfComponent self) {
                const auto clkCls = self.createClockClass();

                clkCls->originIsUnixEpoch(false);
                return clkCls;
            },
            [](const bt2::SelfComponent self) {
                const auto clkCls = self.createClockClass();

                clkCls->originIsUnixEpoch(false);
                return clkCls;
            },
            "message-iterator-class-next-method:clock-class-is-expected", graphMipVersion);
    });
}
