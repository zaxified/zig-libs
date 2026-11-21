#!/bin/bash
# SPDX-License-Identifier: MIT
# Launcher for `zig build bench-mcp`: the bench driver runs `<exe> <work dir> <workload>`.
# MCP_PYTHON overrides the interpreter (default: the oracle venv of tools/sdk_oracle).
exec "${MCP_PYTHON:-$HOME/.local/share/zig-libs/oracle-venvs/mcp/bin/python}" "$(dirname "$0")/main.py" "$@"
