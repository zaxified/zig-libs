// SPDX-License-Identifier: MIT

//! Size probe, "after" half: the SAME two call sites as `probe_before.zig`
//! — one plaintext PUT upload, one plaintext GET + streamRemaining fetch —
//! through the new plaintext-only entry points (`Client.requestPlain` /
//! `Client.putFilePlain`). This binary's call graph must never reach
//! `tls.Client.init`/`ensureCaBundle`/`std.crypto.Certificate` — that is
//! what `run.sh`'s `nm` check proves, and this binary's size relative to
//! `probe_before.zig`'s is the measured saving reported in
//! `../CHANGELOG.md` and `../README.md`.

const std = @import("std");
const http = @import("http");

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client = http.Client.init(io, std.heap.page_allocator, .{});
    defer client.deinit();

    if (client.requestPlain(.get, "http://127.0.0.1:1/x", .{})) |res_val| {
        var res = res_val;
        defer res.deinit();
        var discard_buf: [256]u8 = undefined;
        var discard: std.Io.Writer.Discarding = .init(&discard_buf);
        _ = res.reader().streamRemaining(&discard.writer) catch {};
    } else |_| {}

    const dir = std.Io.Dir.cwd();
    dir.writeFile(io, .{ .sub_path = "sizeprobe_upload.tmp", .data = "hello from the size probe" }) catch {};
    _ = client.putFilePlain("http://127.0.0.1:1/x", dir, "sizeprobe_upload.tmp", .{}) catch {};
    dir.deleteFile(io, "sizeprobe_upload.tmp") catch {};
}
