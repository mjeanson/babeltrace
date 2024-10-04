#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2019 Philippe Proulx <pproulx@efficios.com>
#

SH_TAP=1

if [ -n "${BT_TESTS_SRCDIR:-}" ]; then
	UTILSSH="$BT_TESTS_SRCDIR/utils/utils.sh"
else
	UTILSSH="$(dirname "$0")/../../../utils/utils.sh"
fi

# shellcheck source=../../../utils/utils.sh
source "$UTILSSH"

this_dir_relative="plugins/sink.text.details/succeed"
expect_dir="$BT_TESTS_DATADIR/$this_dir_relative"

# Print the expected stdout file for test with name `$1`, CTF version
# `$2` and MIP version `$3`.
find_expect_file() {
	local test_name="$1"
	local ctf_version="$2"
	local mip_version="$3"

	names=(
		"$expect_dir/$test_name-ctf$ctf_version-mip$mip_version.expect"
		"$expect_dir/$test_name-ctf$ctf_version.expect"
		"$expect_dir/$test_name-mip$mip_version.expect"
		"$expect_dir/$test_name.expect"
	)

	for name in "${names[@]}"; do
		if [[ -f "$name" ]]; then
			echo "$name"
			return
		fi
	done

	echo "Could not find expect file for test $test_name, CTF $ctf_version, MIP $mip_version" >&2
	exit 1
}

test_details() {
	local test_name="$1"
	local trace_name="$2"
	shift 2
	local details_args=("$@")
	local trace_dir="$BT_CTF_TRACES_PATH/1/succeed/$trace_name"
	local expect_path

	for ctf_version in 1 2; do
		local trace_dir="$BT_CTF_TRACES_PATH/${ctf_version}/succeed/$trace_name"

		for mip_version in 0 1; do
			if ! bt_is_valid_ctf_mip_combo $ctf_version $mip_version; then
				continue;
			fi

			expect_path="$(find_expect_file "$test_name" $ctf_version $mip_version)"

			diag "CTF $ctf_version, MIP $mip_version, expect file $expect_path"
			bt_diff_cli "$expect_path" /dev/null \
				--allowed-mip-versions=$mip_version \
				"$trace_dir" -p trace-name=the-trace \
				-c sink.text.details "${details_args[@]+${details_args[@]}}"
			ok $? "CTF $ctf_version: MIP $mip_version: '$test_name' test has the expected output"
		done
	done
}

# This is used for the moment because the source is `src.ctf.fs` and
# such a component can make its stream names contain absolute paths.
test_details_no_stream_name() {
	local test_name="$1"
	local trace_name="$2"
	shift 2
	local details_args=("$@")

	test_details "$test_name" "$trace_name" \
		"${details_args[@]+${details_args[@]}}" -p with-stream-name=no
}

plan_tests 36

test_details_no_stream_name default wk-heartbeat-u
test_details_no_stream_name default-compact wk-heartbeat-u -p compact=yes
test_details_no_stream_name default-compact-without-metadata wk-heartbeat-u -p compact=yes,with-metadata=no
test_details_no_stream_name default-compact-without-time wk-heartbeat-u -p compact=yes,with-time=no
test_details_no_stream_name default-without-data wk-heartbeat-u -p with-data=no
test_details_no_stream_name default-without-data-without-metadata wk-heartbeat-u -p with-data=no,with-metadata=no
test_details_no_stream_name default-without-metadata wk-heartbeat-u -p with-metadata=no
test_details_no_stream_name default-without-names wk-heartbeat-u -p with-stream-name=no,with-trace-name=no,with-stream-class-name=no
test_details_no_stream_name default-without-time wk-heartbeat-u -p with-time=no
test_details_no_stream_name default-without-trace-name wk-heartbeat-u -p with-trace-name=no
test_details_no_stream_name default-without-uuid wk-heartbeat-u -p with-uuid=no
test_details_no_stream_name no-packet-context no-packet-context
