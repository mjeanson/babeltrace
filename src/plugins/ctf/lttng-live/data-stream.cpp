/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#include <sstream>

#include <glib.h>

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "compat/mman.h" /* IWYU pragma: keep  */
#include "cpp-common/bt2/wrap.hpp"
#include "cpp-common/bt2s/make-unique.hpp"
#include "cpp-common/vendor/fmt/format.h"

#include "../common/src/pkt-props.hpp"
#include "data-stream.hpp"

#define STREAM_NAME_PREFIX "stream-"

using namespace bt2c::literals::datalen;

namespace ctf {
namespace src {
namespace live {

Buf CtfLiveMedium::buf(bt2c::DataLen requestedOffsetInStream, bt2c::DataLen minSize)
{
    BT_CPPLOGD("CtfLiveMedium::buf called: stream-id={}, offset-bytes={}, min-size-bytes={}",
               _mLiveStreamIter.stream ? _mLiveStreamIter.stream->id() : -1,
               requestedOffsetInStream.bytes(), minSize.bytes());

    if (_mLiveStreamIter.has_stream_hung_up)
        throw NoData {};

    BT_ASSERT(requestedOffsetInStream >= _mCurPktBegOffsetInStream);
    auto requestedOffsetInPacket = requestedOffsetInStream - _mCurPktBegOffsetInStream;

    BT_ASSERT(_mLiveStreamIter.curPktInfo);

    if (requestedOffsetInPacket == _mLiveStreamIter.curPktInfo->len) {
        _mCurPktBegOffsetInStream += _mLiveStreamIter.curPktInfo->len;
        _mLiveStreamIter.curPktInfo.reset();
        lttng_live_stream_iterator_set_state(&_mLiveStreamIter, LTTNG_LIVE_STREAM_ACTIVE_NO_DATA);
        throw bt2c::TryAgain {};
    }

    auto requestedOffsetInRelay =
        _mLiveStreamIter.curPktInfo->offsetInRelay + requestedOffsetInPacket;
    auto lenUntilEndOfPacket = _mLiveStreamIter.curPktInfo->len - requestedOffsetInPacket;

    auto maxReqLen = bt2c::DataLen::fromBytes(
        _mLiveStreamIter.trace->session->lttng_live_msg_iter->lttng_live_comp->max_query_size);
    auto reqLen = std::min(lenUntilEndOfPacket, maxReqLen);
    uint64_t recvLen;

    _mBuf.resize(reqLen.bytes());

    lttng_live_get_stream_bytes_status status = lttng_live_get_stream_bytes(
        _mLiveStreamIter.trace->session->lttng_live_msg_iter, &_mLiveStreamIter, _mBuf.data(),
        requestedOffsetInRelay.bytes(), reqLen.bytes(), &recvLen);
    switch (status) {
    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_OK:
        _mBuf.resize(recvLen);
        break;

    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_AGAIN:
        BT_CPPLOGD("CtfLiveMedium::buf try again");
        throw bt2c::TryAgain();

    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_EOF:
        BT_CPPLOGD("CtfLiveMedium::buf eof");
        throw NoData();

    case LTTNG_LIVE_GET_STREAM_BYTES_STATUS_ERROR:
        BT_CPPLOGD("CtfLiveMedium::buf error");
        throw bt2c::Error();
    }

    const Buf buf {_mBuf.data(), bt2c::DataLen::fromBytes(_mBuf.size())};

    BT_CPPLOGD("CtfLiveMedium::buf returns: stream-id={}, buf-addr={}, buf-size-bytes={}",
               _mLiveStreamIter.stream ? _mLiveStreamIter.stream->id() : -1, fmt::ptr(buf.addr()),
               buf.size().bytes());

    return buf;
}

} /* namespace live */
} /* namespace src */
} /* namespace ctf */

lttng_live_iterator_status
lttng_live_stream_iterator_create_msg_iter(lttng_live_stream_iterator *liveStreamIter)
{
    BT_ASSERT(!liveStreamIter->msg_iter);
    BT_ASSERT(!liveStreamIter->stream);
    lttng_live_trace *trace = liveStreamIter->trace;
    lttng_live_msg_iter *liveMsgIter = trace->session->lttng_live_msg_iter;

    auto tempMedium = bt2s::make_unique<ctf::src::live::CtfLiveMedium>(*liveStreamIter);
    const ctf::src::TraceCls *ctfTc = liveStreamIter->trace->metadata->traceCls();
    BT_ASSERT(ctfTc);
    ctf::src::PktProps pktProps =
        ctf::src::readPktProps(*ctfTc, std::move(tempMedium), 0_bytes, liveStreamIter->logger);

    bt2::OptionalBorrowedObject<bt2::TraceClass> tc = ctfTc->libCls();
    BT_ASSERT(tc);
    BT_ASSERT(liveStreamIter->ctf_stream_class_id.is_set);
    BT_ASSERT(trace->trace);

    auto sc = tc->streamClassById(liveStreamIter->ctf_stream_class_id.value);
    if (!sc) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW_SPEC(liveStreamIter->logger, bt2::Error,
                                               "No stream class with id {}",
                                               liveStreamIter->ctf_stream_class_id.value);
    }

    bt_stream *streamPtr;
    if (pktProps.dataStreamId) {
        streamPtr = bt_stream_create_with_id(sc->libObjPtr(), trace->trace->libObjPtr(),
                                             *pktProps.dataStreamId);
    } else {
        /*
         * No stream instance ID in the stream. It's possible
         * to encounter this situation with older version of
         * LTTng. In these cases, use the viewer_stream_id that
         * is unique for a live viewer session.
         */
        streamPtr = bt_stream_create_with_id(sc->libObjPtr(), trace->trace->libObjPtr(),
                                             liveStreamIter->viewer_stream_id);
    }
    BT_ASSERT(streamPtr);
    liveStreamIter->stream = bt2::Stream::Shared::createWithoutRef(streamPtr);
    liveStreamIter->stream->name(liveStreamIter->name);

    auto medium = bt2s::make_unique<ctf::src::live::CtfLiveMedium>(*liveStreamIter);
    liveStreamIter->msg_iter.emplace(bt2::wrap(liveMsgIter->self_msg_iter), *ctfTc,
                                     liveStreamIter->trace->metadata->metadataStreamUuid(),
                                     *liveStreamIter->stream, std::move(medium),
                                     ctf::src::MsgIterQuirks {}, liveStreamIter->logger);
    return LTTNG_LIVE_ITERATOR_STATUS_OK;
}

enum lttng_live_iterator_status lttng_live_lazy_msg_init(struct lttng_live_session *session,
                                                         bt_self_message_iterator *self_msg_iter)
{
    if (!session->lazy_stream_msg_init) {
        return LTTNG_LIVE_ITERATOR_STATUS_OK;
    }

    BT_CPPLOGD_SPEC(session->logger,
                    "Lazily initializing self message iterator for live session: "
                    "session-id={}, self-msg-iter-addr={}",
                    session->id, fmt::ptr(self_msg_iter));

    for (lttng_live_trace::UP& trace : session->traces) {
        for (lttng_live_stream_iterator::UP& stream_iter : trace->stream_iterators) {
            if (stream_iter->msg_iter) {
                continue;
            }

            const ctf::src::TraceCls *ctfTraceCls = trace->metadata->traceCls();
            BT_CPPLOGD_SPEC(session->logger,
                            "Creating CTF message iterator: session-id={}, ctf-tc-addr={}, "
                            "stream-iter-name={}, self-msg-iter-addr={}",
                            session->id, fmt::ptr(ctfTraceCls), stream_iter->name.c_str(),
                            fmt::ptr(self_msg_iter));
        }
    }

    session->lazy_stream_msg_init = false;

    return LTTNG_LIVE_ITERATOR_STATUS_OK;
}

struct lttng_live_stream_iterator *
lttng_live_stream_iterator_create(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                  uint64_t stream_id)
{
    std::stringstream nameSs;

    BT_ASSERT(session);
    BT_ASSERT(session->lttng_live_msg_iter);
    BT_ASSERT(session->lttng_live_msg_iter->lttng_live_comp);

    const auto trace = lttng_live_session_borrow_or_create_trace_by_id(session, ctf_trace_id);
    if (!trace) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(session->logger, "Failed to borrow CTF trace.");
        return nullptr;
    }

    auto stream_iter = bt2s::make_unique<lttng_live_stream_iterator>(session->logger);

    stream_iter->trace = trace;
    stream_iter->state = LTTNG_LIVE_STREAM_ACTIVE_NO_DATA;
    stream_iter->viewer_stream_id = stream_id;

    stream_iter->ctf_stream_class_id.is_set = false;
    stream_iter->ctf_stream_class_id.value = UINT64_MAX;

    stream_iter->last_inactivity_ts.is_set = false;
    stream_iter->last_inactivity_ts.value = 0;

    nameSs << STREAM_NAME_PREFIX << stream_iter->viewer_stream_id;
    stream_iter->name = nameSs.str();

    const auto ret = stream_iter.get();
    trace->stream_iterators.emplace_back(std::move(stream_iter));

    /* Track the number of active stream iterator. */
    session->lttng_live_msg_iter->active_stream_iter++;

    return ret;
}

void lttng_live_stream_iterator_set_stream_class(lttng_live_stream_iterator *streamIter,
                                                 uint64_t ctfStreamClsId)
{
    if (streamIter->ctf_stream_class_id.is_set) {
        BT_ASSERT(streamIter->ctf_stream_class_id.value == ctfStreamClsId);
        return;
    } else {
        streamIter->ctf_stream_class_id.value = ctfStreamClsId;
        streamIter->ctf_stream_class_id.is_set = true;
    }
}

lttng_live_stream_iterator::~lttng_live_stream_iterator()
{
    /* Track the number of active stream iterator. */
    this->trace->session->lttng_live_msg_iter->active_stream_iter--;
}
