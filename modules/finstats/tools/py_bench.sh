#!/bin/sh
# SPDX-License-Identifier: MIT
# Wrapper so tools/bench.zig can run the Python side as "<exe> <work dir> <workload>".
# FINSTATS_BENCH_PY: the oracle venv's python (empyrical-reloaded, quantstats,
# numpy, scipy installed; recipe in oracle.py). Default: the venv from oracle.py.
PY="${FINSTATS_BENCH_PY:-$HOME/.local/share/zig-libs/oracle-venvs/finstats/bin/python}"
exec "$PY" "$(dirname "$0")/py_bench.py" "$@"
