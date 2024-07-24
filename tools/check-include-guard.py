#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2024 Simon Marchi <simon.marchi@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

# Usage: check-include-guard.py [--fix] FILE
#
# Checks (and optionally tries to fix) the C/C++ header include guard
# names and format of `FILE`.
#
# With `--fix`, this script fixes the include guard names in place.

import re
import sys
import pathlib
import argparse


class _Oops(Exception):
    def __init__(self, msg: str):
        self._msg = msg

    @property
    def msg(self):
        return self._msg


def _make_expected_ig_name(filename: pathlib.Path):
    # Normalize `filename` (e.g. remove `..`) and make it relative to
    # the root of the source tree.
    root = pathlib.Path(__file__).parent.parent.resolve(strict=True)
    filename = filename.absolute().resolve(strict=True).relative_to(root)

    expected_ig_name = re.sub(r"[/.-]", "_", str(filename)).upper()
    expected_ig_name = re.sub(r"^SRC_", "", expected_ig_name)
    return "BABELTRACE_" + expected_ig_name


def _check_file(filename: pathlib.Path, fix: bool):
    with open(filename) as f:
        contents = f.read()

    write_file = False

    # Top part
    top_re = re.compile(r"^(/\*.+?\*/)\n\n#ifndef (\w+)\n#define (\w+)\n", re.DOTALL)
    top_m = top_re.match(contents)

    if not top_m:
        raise _Oops(
            "Top of the file doesn't have the expected form: block comment, empty line, and then two include guard lines"
        )

    expected_ig_name = _make_expected_ig_name(filename)

    if fix:
        contents = top_re.sub(
            rf"\1\n\n#ifndef {expected_ig_name}\n#define {expected_ig_name}\n",
            contents,
        )
        write_file = True
    else:
        if top_m.group(2) != expected_ig_name:
            raise _Oops(
                f"In `#ifndef {top_m.group(2)}` include guard line: expecting `#ifndef {expected_ig_name}`"
            )

        if top_m.group(3) != expected_ig_name:
            raise _Oops(
                f"In `#define {top_m.group(3)}` include guard line: expecting `#define {expected_ig_name}`"
            )

    # Bottom part
    bottom_re = re.compile(r"\n\n#endif(?: /\* (\w+) \*/)?\n$")
    bottom_m = bottom_re.search(contents)

    if not bottom_m:
        raise _Oops("Missing final `#endif` include guard line and trailing empty line")

    if fix:
        contents = bottom_re.sub(f"\n\n#endif /* {expected_ig_name} */\n", contents)
        write_file = True
    else:
        if bottom_m.group(1) != expected_ig_name:
            raise _Oops(
                f"In bottom `#endif` include guard line: expecting `#endif /* {expected_ig_name} */`"
            )

    if write_file:
        with open(filename, "w") as f:
            f.write(contents)


def _main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "-f",
        "--fix",
        action="store_true",
        help="attempt to fix the include guards of FILE",
    )
    argparser.add_argument("FILE")
    args = argparser.parse_args()
    filename = pathlib.Path(args.FILE)

    try:
        _check_file(filename, args.fix)
    except _Oops as exc:
        print(f"{filename}: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
