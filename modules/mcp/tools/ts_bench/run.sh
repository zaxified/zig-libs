#!/bin/bash
# SPDX-License-Identifier: MIT
# Launcher for `zig build bench-mcp`: the bench driver runs `<exe> <work dir> <workload>`.
# MCP_NODE overrides the Node binary (default: the tarball of tools/sdk_oracle/drive_ts.mjs).
exec "${MCP_NODE:-$HOME/.local/share/zig-libs/oracle-bin/node/bin/node}" "$(dirname "$0")/main.mjs" "$@"
