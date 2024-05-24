/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 Francis Deslauriers <francis.deslauriers@efficios.com>
 * Copyright 2016 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2010-2011 EfficiOS Inc. and Linux Foundation
 */

#include "cpp-common/bt2s/make-unique.hpp"

#include "../common/src/metadata/tsdl/ctf-meta-configure-ir-trace.hpp"
#include "lttng-live.hpp"
#include "metadata.hpp"

#define TSDL_MAGIC 0x75d11d57

struct packet_header
{
    uint32_t magic;
    uint8_t uuid[16];
    uint32_t checksum;
    uint32_t content_size;
    uint32_t packet_size;
    uint8_t compression_scheme;
    uint8_t encryption_scheme;
    uint8_t checksum_scheme;
    uint8_t major;
    uint8_t minor;
} __attribute__((__packed__));

static bool stream_classes_all_have_default_clock_class(bt2::ConstTraceClass tc,
                                                        const bt2c::Logger& logger)
{
    for (std::uint64_t i = 0; i < tc.length(); ++i) {
        auto sc = tc[i];
        auto cc = sc.defaultClockClass();

        if (!cc) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(logger,
                                         "Stream class doesn't have a default clock class: "
                                         "sc-id={}, sc-name=\"{}\"",
                                         sc.id(), sc.name());
            return false;
        }
    }

    return true;
}
/*
 * Iterate over the stream classes and returns the first clock class
 * encountered. This is useful to create message iterator inactivity message as
 * we don't need a particular clock class.
 */
static bt2::ConstClockClass borrow_any_clock_class(bt2::ConstTraceClass tc)
{
    return *tc[0].defaultClockClass();
}

enum lttng_live_iterator_status lttng_live_metadata_update(struct lttng_live_trace *trace)
{
    struct lttng_live_session *session = trace->session;
    struct lttng_live_metadata *metadata = trace->metadata.get();
    bool keep_receiving;
    enum lttng_live_get_one_metadata_status metadata_status;

    BT_CPPLOGD_SPEC(metadata->logger, "Updating metadata for trace: session-id={}, trace-id={}",
                    session->id, trace->id);

    /* No metadata stream yet. */
    if (!metadata) {
        if (session->closed) {
            /*
             * The session is closed AND we never received any
             * metadata this indicates that we will never receive
             * any metadata.
             */
            return LTTNG_LIVE_ITERATOR_STATUS_END;
        } else if (session->new_streams_needed) {
            return LTTNG_LIVE_ITERATOR_STATUS_AGAIN;
        } else {
            session->new_streams_needed = true;
            return LTTNG_LIVE_ITERATOR_STATUS_CONTINUE;
        }
    }

    if (trace->metadata_stream_state != LTTNG_LIVE_METADATA_STREAM_STATE_NEEDED) {
        return LTTNG_LIVE_ITERATOR_STATUS_OK;
    }

    keep_receiving = true;
    /* Grab all available metadata. */
    std::vector<uint8_t> metadataBuf;
    while (keep_receiving) {
        /*
         * lttng_live_get_one_metadata_packet() asks the Relay Daemon
         * for new metadata. If new metadata is received, the function
         * writes it to the provided file handle and updates the
         * reply_len output parameter. We call this function in loop
         * until it returns _END meaning that no new metadata is
         * available.
         * We may receive a _CLOSED status if the metadata stream we
         * are requesting is no longer available on the relay.
         * If we receive an _ERROR status, it means there was a
         * networking, allocating, or some other unrecoverable error.
         */
        metadata_status = lttng_live_get_one_metadata_packet(trace, metadataBuf);

        switch (metadata_status) {
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_OK:
            break;
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_END:
            keep_receiving = false;
            break;
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_CLOSED:
            BT_CPPLOGD_SPEC(
                metadata->logger,
                "Metadata stream was closed by the Relay, the trace is no longer active: "
                "trace-id={}, metadata-stream-id={}",
                trace->id, metadata->stream_id);
            /*
             * The stream was closed and we received everything
             * there was to receive for this metadata stream.
             * We go on with the decoding of what we received. So
             * that data stream can be decoded.
             */
            keep_receiving = false;
            trace->metadata_stream_state = LTTNG_LIVE_METADATA_STREAM_STATE_CLOSED;
            break;
        case LTTNG_LIVE_GET_ONE_METADATA_STATUS_ERROR:
            BT_CPPLOGE_APPEND_CAUSE_SPEC(metadata->logger,
                                         "Error getting one trace metadata packet: trace-id={}",
                                         trace->id);
            return LTTNG_LIVE_ITERATOR_STATUS_ERROR;
        default:
            bt_common_abort();
        }
    }

    if (metadataBuf.empty()) {
        if (!trace->trace) {
            return LTTNG_LIVE_ITERATOR_STATUS_AGAIN;
        }

        /* The relay sent zero bytes of metadata. */
        trace->metadata_stream_state = LTTNG_LIVE_METADATA_STREAM_STATE_NOT_NEEDED;
        return LTTNG_LIVE_ITERATOR_STATUS_OK;
    }

    /*
     * The call to ctf_metadata_decoder_append_content() will append
     * new metadata to our current trace class.
     */
    BT_CPPLOGD_SPEC(metadata->logger, "Appending new metadata to the ctf_trace class");
    metadata->parseSection(metadataBuf);
    if (!trace->trace) {
        const ctf::src::TraceCls *ctfTraceCls = metadata->traceCls();
        BT_ASSERT(ctfTraceCls);
        bt2::OptionalBorrowedObject<bt2::TraceClass> irTraceCls = ctfTraceCls->libCls();

        if (irTraceCls) {
            trace->trace = irTraceCls->instantiate();

            ctf_trace_class_configure_ir_trace(*ctfTraceCls, *trace->trace,
                                               metadata->selfComp().graphMipVersion(),
                                               metadata->logger);

            if (!stream_classes_all_have_default_clock_class(trace->trace->cls(),
                                                             metadata->logger)) {
                /* Error logged in function. */
                return LTTNG_LIVE_ITERATOR_STATUS_ERROR;
            }

            trace->clock_class = borrow_any_clock_class(trace->trace->cls());
        }
    }

    /* The metadata was updated successfully. */
    trace->metadata_stream_state = LTTNG_LIVE_METADATA_STREAM_STATE_NOT_NEEDED;

    return LTTNG_LIVE_ITERATOR_STATUS_OK;
}

int lttng_live_metadata_create_stream(struct lttng_live_session *session, uint64_t ctf_trace_id,
                                      uint64_t stream_id)
{
    auto metadata = bt2s::make_unique<lttng_live_metadata>(session->selfComp, session->logger);

    metadata->stream_id = stream_id;

    const auto trace = lttng_live_session_borrow_or_create_trace_by_id(session, ctf_trace_id);

    if (!trace) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(session->logger, "Failed to borrow trace");
        return -1;
    }

    trace->metadata = std::move(metadata);
    return 0;
}
