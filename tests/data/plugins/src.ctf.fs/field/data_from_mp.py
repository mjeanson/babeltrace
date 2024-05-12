# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 EfficiOS Inc.
#
# pyright: strict, reportTypeCommentUsage=false

import os
import string
import argparse

import normand
import moultipart


def _make_ctf_1_metadata(payload_fc: str):
    if "@" in payload_fc:
        payload_fc = payload_fc.replace("@", "root")
    else:
        payload_fc += " root"

    return string.Template(
        """\
/* CTF 1.8 */

trace {
    major = 1;
    minor = 8;
    byte_order = le;
};

typealias integer { size = 8; } := u8;
typealias integer { size = 16; } := u16;
typealias integer { size = 32; } := u32;
typealias integer { size = 64; } := u64;
typealias integer { size = 8; byte_order = le; } := u8le;
typealias integer { size = 16; byte_order = le; } := u16le;
typealias integer { size = 32; byte_order = le; } := u32le;
typealias integer { size = 64; byte_order = le; } := u64le;
typealias integer { size = 8; byte_order = be; } := u8be;
typealias integer { size = 16; byte_order = be; } := u16be;
typealias integer { size = 32; byte_order = be; } := u32be;
typealias integer { size = 64; byte_order = be; } := u64be;
typealias integer { signed = true; size = 8; } := i8;
typealias integer { signed = true; size = 16; } := i16;
typealias integer { signed = true; size = 32; } := i32;
typealias integer { signed = true; size = 64; } := i64;
typealias integer { signed = true; size = 8; byte_order = le; } := i8le;
typealias integer { signed = true; size = 16; byte_order = le; } := i16le;
typealias integer { signed = true; size = 32; byte_order = le; } := i32le;
typealias integer { signed = true; size = 64; byte_order = le; } := i64le;
typealias integer { signed = true; size = 8; byte_order = be; } := i8be;
typealias integer { signed = true; size = 16; byte_order = be; } := i16be;
typealias integer { signed = true; size = 32; byte_order = be; } := i32be;
typealias integer { signed = true; size = 64; byte_order = be; } := i64be;
typealias floating_point { exp_dig = 8; mant_dig = 24; } := flt32;
typealias floating_point { exp_dig = 11; mant_dig = 53; } := flt64;
typealias floating_point { exp_dig = 8; mant_dig = 24; byte_order = le; } := flt32le;
typealias floating_point { exp_dig = 11; mant_dig = 53; byte_order = le; } := flt64le;
typealias floating_point { exp_dig = 8; mant_dig = 24; byte_order = be; } := flt32be;
typealias floating_point { exp_dig = 11; mant_dig = 53; byte_order = be; } := flt64be;
typealias string { encoding = UTF8; } := nt_str;

event {
    name = the_event;
    fields := struct {
        ${payload_fc};
    };
};
"""
    ).substitute(payload_fc=payload_fc)


def _make_ctf_2_metadata(payload_fc: str):
    return string.Template(
        """\
\x1e{
  "type": "preamble",
  "version": "2"
}
\x1e{
  "type": "field-class-alias",
  "name": "u8le",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 8,
    "byte-order": "little-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u16le",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 16,
    "byte-order": "little-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u32le",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 32,
    "byte-order": "little-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u64le",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 64,
    "byte-order": "little-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u8",
  "field-class": "u8le"
}
\x1e{
  "type": "field-class-alias",
  "name": "u16",
  "field-class": "u16le"
}
\x1e{
  "type": "field-class-alias",
  "name": "u32",
  "field-class": "u32le"
}
\x1e{
  "type": "field-class-alias",
  "name": "u64",
  "field-class": "u64le"
}
\x1e{
  "type": "field-class-alias",
  "name": "u8be",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 8,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u16be",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 16,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u32be",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 32,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u64be",
  "field-class": {
    "type": "fixed-length-unsigned-integer",
    "length": 64,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "i8le",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 8,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "i16le",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 16,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "i32le",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 32,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "i64le",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 64,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "i8be",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 8,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "i16be",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 16,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "i32be",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 32,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "u64be",
  "field-class": {
    "type": "fixed-length-signed-integer",
    "length": 64,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "flt32le",
  "field-class": {
    "type": "fixed-length-floating-point-number",
    "length": 32,
    "byte-order": "little-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "flt64le",
  "field-class": {
    "type": "fixed-length-floating-point-number",
    "length": 64,
    "byte-order": "little-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "flt32",
  "field-class": "flt32le"
}
\x1e{
  "type": "field-class-alias",
  "name": "flt64",
  "field-class": "flt64le"
}
\x1e{
  "type": "field-class-alias",
  "name": "flt32be",
  "field-class": {
    "type": "fixed-length-floating-point-number",
    "length": 32,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "flt64be",
  "field-class": {
    "type": "fixed-length-floating-point-number",
    "length": 64,
    "byte-order": "big-endian",
    "alignment": 8
  }
}
\x1e{
  "type": "field-class-alias",
  "name": "nt-str",
  "field-class": {
    "type": "null-terminated-string"
  }
}
\x1e{
  "type": "data-stream-class"
}
\x1e{
  "type": "event-record-class",
  "payload-field-class": {
    "type": "structure",
    "member-field-classes": [
      {
        "name": "root",
        "field-class": ${payload_fc}
      }
    ]
  }
}
"""
    ).substitute(payload_fc=payload_fc)


def _make_ctf_metadata(payload_fc: str):
    if payload_fc.startswith("{") or payload_fc.startswith('"'):
        # CTF 2
        return _make_ctf_2_metadata(payload_fc)
    else:
        # Assume CTF 1.8
        return _make_ctf_1_metadata(payload_fc)


def _make_ctf_1_data(normand_text: str):
    # Default to little-endian because that's also the default in
    # _make_ctf_1_metadata() and _make_ctf_2_metadata() above.
    return normand.parse("!le\n" + normand_text).data


def _create_files_from_mp(mp_path: str, output_dir: str):
    trace_dir = os.path.join(output_dir, "trace")
    expect_path = os.path.join(output_dir, "expect")
    metadata_path = os.path.join(trace_dir, "metadata")
    data_path = os.path.join(trace_dir, "data")
    os.makedirs(trace_dir, exist_ok=True)

    with open(mp_path, "r") as f:
        parts = moultipart.parse(f)

    with open(metadata_path, "w") as f:
        f.write(_make_ctf_metadata(parts[0].content.strip()))

    with open(data_path, "wb") as f:
        f.write(_make_ctf_1_data(parts[1].content))

    with open(expect_path, "w") as f:
        f.write(parts[2].content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mp_path", metavar="MP-PATH", help="moultipart document to process"
    )
    parser.add_argument(
        "output_dir",
        metavar="OUTPUT-DIR",
        help="output directory for the CTF trace and expectation file",
    )
    args = parser.parse_args()
    _create_files_from_mp(args.mp_path, args.output_dir)
