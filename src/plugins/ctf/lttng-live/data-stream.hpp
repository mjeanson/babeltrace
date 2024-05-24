/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_DATA_STREAM_HPP
#define BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_DATA_STREAM_HPP

#include <stdint.h>

#include "lttng-live.hpp"

enum lttng_live_iterator_status lttng_live_lazy_msg_init(struct lttng_live_session *session,
                                                         bt_self_message_iterator *self_msg_iter);

struct lttng_live_stream_iterator *
lttng_live_stream_iterator_create(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                  uint64_t stream_id);

namespace ctf {
namespace src {
namespace live {

struct CtfLiveMedium : Medium
{
    CtfLiveMedium(lttng_live_stream_iterator& liveStreamIter) :
        _mLogger {liveStreamIter.logger, "PLUGIN/SRC.CTF.LTTNG-LIVE/CTF-LIVE-MEDIUM"},
        _mLiveStreamIter(liveStreamIter)
    {
    }

    Buf buf(bt2c::DataLen offset, bt2c::DataLen minSize) override;

private:
    bt2c::Logger _mLogger;
    lttng_live_stream_iterator& _mLiveStreamIter;

    bt2c::DataLen _mCurPktBegOffsetInStream = bt2c::DataLen::fromBits(0);
    std::vector<uint8_t> _mBuf;
};

} /* namespace live */
} /* namespace src */
} /* namespace ctf */

lttng_live_iterator_status
lttng_live_stream_iterator_create_msg_iter(lttng_live_stream_iterator *liveStreamIter);

#endif /* BABELTRACE_PLUGINS_CTF_LTTNG_LIVE_DATA_STREAM_HPP */
