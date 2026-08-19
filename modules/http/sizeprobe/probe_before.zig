// SPDX-License-Identifier: MIT

//! Size probe, "before" half: mirrors a device agent's two call sites —
//! one plaintext PUT upload, one plaintext GET + streamRemaining fetch, both
//! to an IP literal — through the ORIGINAL, TLS-capable entry points
//! (`Client.request` / `Client.putFile`) that every existing caller
//! (`request`/`requestStreaming`/`putFile`) still uses
//! unchanged. This binary's size is the baseline half of the plaintext-only
//! client A/B measured in `../README.md`'s "Plaintext-only client" section
//! and `../CHANGELOG.md`. See `run.sh` for how it is built and compared
//! against `probe_after.zig`.
//!
//! Both network calls are expected to fail at runtime (127.0.0.1:1 refuses
//! the connection) — that is fine and deliberate: this probe measures the
//! LINKED BINARY, which contains the whole reachable call graph regardless
//! of which runtime branch actually executes, not a live exchange. See
//! `dialPlain`'s doc comment in `../src/Client.zig` for why that is exactly
//! the mechanism this split relies on.

const std = @import("std");
const http = @import("http");

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = http.Client.init(io, std.heap.page_allocator, .{});
    defer client.deinit();

    if (client.request(.get, "http://127.0.0.1:1/x", .{})) |res_val| {
        var res = res_val;
        defer res.deinit();
        var discard_buf: [256]u8 = undefined;
        var discard: std.Io.Writer.Discarding = .init(&discard_buf);
        _ = res.reader().streamRemaining(&discard.writer) catch {};
    } else |_| {}

    const dir = std.Io.Dir.cwd();
    dir.writeFile(io, .{ .sub_path = "sizeprobe_upload.tmp", .data = "hello from the size probe" }) catch {};
    _ = client.putFile("http://127.0.0.1:1/x", dir, "sizeprobe_upload.tmp", .{}) catch {};
    dir.deleteFile(io, "sizeprobe_upload.tmp") catch {};
}
