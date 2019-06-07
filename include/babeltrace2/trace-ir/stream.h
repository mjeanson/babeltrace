#ifndef BABELTRACE_TRACE_IR_STREAM_H
#define BABELTRACE_TRACE_IR_STREAM_H

/*
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2013, 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The Common Trace Format (CTF) Specification is available at
 * http://www.efficios.com/ctf
 */

/* For bt_trace, bt_stream, bt_stream_class */
#include <babeltrace2/types.h>

/* For bt_stream_status */
#include <babeltrace2/trace-ir/stream-const.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bt_stream *bt_stream_create(bt_stream_class *stream_class,
		bt_trace *trace);

extern bt_stream *bt_stream_create_with_id(
		bt_stream_class *stream_class,
		bt_trace *trace, uint64_t id);

extern bt_trace *bt_stream_borrow_trace(bt_stream *stream);

extern bt_stream_class *bt_stream_borrow_class(bt_stream *stream);

extern bt_stream_status bt_stream_set_name(bt_stream *stream,
		const char *name);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_TRACE_IR_STREAM_H */
