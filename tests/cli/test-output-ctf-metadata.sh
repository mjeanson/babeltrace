#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
#

SH_TAP=1

if [ -n "${BT_TESTS_SRCDIR:-}" ]; then
	UTILSSH="$BT_TESTS_SRCDIR/utils/utils.sh"
else
	UTILSSH="$(dirname "$0")/../utils/utils.sh"
fi

# shellcheck source=../utils/utils.sh
source "$UTILSSH"

NUM_TESTS=3

plan_tests $NUM_TESTS

tmp_metadata=$(mktemp)
tmp_stderr=$(mktemp)

# Test a valid trace directory.
bt_cli "$tmp_metadata" "$tmp_stderr" -o ctf-metadata "${BT_CTF_TRACES_PATH}/1/succeed/wk-heartbeat-u"
ok $? "Run babeltrace -o ctf-metadata with a valid trace directory, correct exit status"

bt_diff "${BT_TESTS_DATADIR}/cli/test-output-ctf-metadata.ref" "$tmp_metadata"
ok $? "Run babeltrace -o ctf-metadata with a valid trace directory, correct output"

# Test an invalid trace directory.
bt_cli "$tmp_metadata" "$tmp_stderr" -o ctf-metadata "${BT_CTF_TRACES_PATH}"
isnt $? 0 "Run babeltrace -o ctf-metadata with an invalid trace directory, expecting failure"

rm -f "$tmp_metadata"
rm -f "$tmp_stderr"
