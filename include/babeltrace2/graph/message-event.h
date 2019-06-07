#ifndef BABELTRACE_GRAPH_MESSAGE_EVENT_H
#define BABELTRACE_GRAPH_MESSAGE_EVENT_H

/*
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
 */

#include <stdint.h>

/*
 * For bt_self_message_iterator, bt_event, bt_packet,
 * bt_event_class, bt_message
 */
#include <babeltrace2/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern
bt_message *bt_message_event_create(
		bt_self_message_iterator *message_iterator,
		const bt_event_class *event_class,
		const bt_packet *packet);

extern
bt_message *bt_message_event_create_with_default_clock_snapshot(
		bt_self_message_iterator *message_iterator,
		const bt_event_class *event_class,
		const bt_packet *packet, uint64_t raw_clock_value);

extern bt_event *bt_message_event_borrow_event(
		bt_message *message);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_GRAPH_MESSAGE_EVENT_H */
