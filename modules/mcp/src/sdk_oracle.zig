// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: the official MCP Python SDK (run as a black
//! box by `tools/sdk_oracle/drive.py`, its source not read) drove the catalog
//! of `sdk_oracle_catalog.zig` over stdio once per protocol era — the
//! `initialize` session and the stateless 2026-07-28 path, multi round-trip
//! included — and its typed client accepted every answer (40 checks in
//! `drive.py`, one of them the SDK refusing a stub's malformed `tools/list`,
//! so its acceptance means something). The exact lines it sent and the exact lines the server
//! answered are frozen in `sdk_oracle_vectors.zig`; this test feeds the same
//! requests through `Server.handleMessage` and requires the same answers, byte
//! for byte. A change to the module's wire output fails here until the SDK
//! has accepted the new bytes (re-run `drive.py`).
//!
//! One judged departure of the SDK's, not ours: on the 2026-07-28 path it
//! still sends `ping`, which that revision removed (changelog, major change
//! 5); the server answers -32601 and `drive.py` checks for exactly that.

const std = @import("std");
const testing = std.testing;
const mcp = @import("root.zig");
const vectors = @import("sdk_oracle_vectors.zig");
const C = @import("sdk_oracle_catalog.zig").Catalog(mcp);

test "sdk oracle: every answer the MCP Python SDK accepted is what the server still answers" {
    for (vectors.eras) |era| {
        var server = mcp.Server.init(testing.allocator, C.info);
        defer server.deinit();
        try C.register(&server);
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        var lines = std.mem.splitScalar(u8, era.requests, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try server.handleMessage(line, &out.writer);
        }
        if (!std.mem.eql(u8, out.written(), era.responses)) {
            std.debug.print("sdk oracle {s}: answers differ from what SDK {s} accepted\n  want: {s}\n  got:  {s}\n", .{
                era.name, vectors.sdk_version, era.responses, out.written(),
            });
            return error.OracleDisagrees;
        }
    }
}
