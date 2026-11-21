#!/bin/sh
# SPDX-License-Identifier: MIT
# benchkit runs `<exe> <work dir> <workload>`; this is the pyarrow side of tools/bench.zig.
here=$(dirname "$0")
py="${ARROW_PYTHON:-$here/../../../tools/arrow-venv/bin/python}"
[ -x "$py" ] || py=python3
exec "$py" "$here/bench.py" "$@"
