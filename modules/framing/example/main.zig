// SPDX-License-Identifier: MIT

//! What a consumer building a length-prefixed protocol on `framing` does:
//! frame three JSON envelope messages onto one wire, then feed that wire back
//! through a reader that hands out only a FEW bytes per read regardless of
//! what is asked for — the way a real socket or pipe actually delivers bytes
//! — so the 4-byte header and the payload of each frame straddle several
//! short reads instead of arriving whole. `framing.readFrame` must not care.
//! Then deliberately break the stream the two ways a peer (or an attacker
//! feeding it directly) would: truncate a frame mid-payload, and announce a
//! length past the configured cap, on both the write side and the read side.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const framing = @import("framing");

/// A domain-free tagged union standing in for a real protocol's message set
/// (`framing`'s own tests use one shaped just like it) — proves
/// `EnvelopeCodec` from outside without importing any application type.
const DemoMsg = union(enum) {
    ping: struct { seq: u32 },
    status: struct { ok: bool, note: []const u8 },
    bye: struct {},
};

const Codec = framing.EnvelopeCodec(DemoMsg);

/// A `std.Io.Reader` that hands back at most `chunk` bytes per underlying
/// `stream()` call, no matter how much the caller asked for — so a 4-byte
/// frame header, or a payload longer than `chunk`, is assembled from SEVERAL
/// short reads instead of one. Modeled on `ipcbus.FdReader`, the real
/// fd-backed adapter this module's SPEC says a socket consumer uses; this one
/// dribbles from an in-memory buffer instead of a live fd, so the boundary
/// behavior is deterministic and needs no OS pipe or second thread.
const DribbleReader = struct {
    data: []const u8,
    pos: usize = 0,
    chunk: usize,
    interface: std.Io.Reader,

    fn init(data: []const u8, buffer: []u8, chunk: usize) DribbleReader {
        return .{
            .data = data,
            .chunk = chunk,
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *DribbleReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (self.pos >= self.data.len) return error.EndOfStream;
        const want = @min(self.chunk, self.data.len - self.pos);
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        const n = @min(want, dest.len);
        @memcpy(dest[0..n], self.data[self.pos..][0..n]);
        io_w.advance(n);
        self.pos += n;
        return n;
    }
};

pub fn main() !void {
    // A DebugAllocator that panics on leak makes this example a leak
    // detector for the module's ownership contract (CONVENTIONS.md §7.2) —
    // in particular for the error-partway-through-an-allocating-function
    // shape: `writeFramed`/`readFrameAlloc` both allocate before they can
    // fail, and a real leak there would only show up under a real GPA, never
    // under the ArenaAllocator a module's own tests are free to use.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── build a small stream of three framed envelope messages ─────────────
    var wire: std.Io.Writer.Allocating = .init(gpa);
    defer wire.deinit();

    try Codec.writeFramed(.{ .ping = .{ .seq = 1 } }, gpa, &wire.writer, .{});
    try Codec.writeFramed(.{ .status = .{ .ok = true, .note = "warming up" } }, gpa, &wire.writer, .{});
    try Codec.writeFramed(.{ .bye = .{} }, gpa, &wire.writer, .{});
    const wire_bytes = wire.writer.buffered();
    std.debug.print("wrote {d} bytes across 3 frames\n", .{wire_bytes.len});

    // ── read them back off a reader that dribbles 3 bytes at a time ────────
    // 3 is smaller than the 4-byte length header AND smaller than every
    // payload here, so both the header and every payload straddle multiple
    // short reads.
    var rbuf: [8]u8 = undefined;
    var dr: DribbleReader = .init(wire_bytes, &rbuf, 3);

    var frame_buf: [256]u8 = undefined;
    const p1 = try framing.readFrame(&dr.interface, &frame_buf, .{});
    var m1 = try Codec.parse(gpa, p1);
    defer m1.deinit();
    std.debug.assert(m1.value == .ping and m1.value.ping.seq == 1);

    const p2 = try framing.readFrame(&dr.interface, &frame_buf, .{});
    var m2 = try Codec.parse(gpa, p2);
    defer m2.deinit();
    std.debug.assert(m2.value == .status and m2.value.status.ok);
    std.debug.assert(std.mem.eql(u8, m2.value.status.note, "warming up"));

    const p3 = try framing.readFrame(&dr.interface, &frame_buf, .{});
    var m3 = try Codec.parse(gpa, p3);
    defer m3.deinit();
    std.debug.assert(m3.value == .bye);
    std.debug.print("dribble-fed reader (3 bytes/read): all 3 frames decoded intact\n", .{});

    // The stream is now exhausted: a 4th read must fail by name, not hang or
    // return a bogus zero-length frame.
    if (framing.readFrame(&dr.interface, &frame_buf, .{})) |_| {
        unreachable;
    } else |err| switch (err) {
        error.EndOfStream => std.debug.print("4th read past end of stream: EndOfStream (expected)\n", .{}),
        else => return err,
    }

    // ── a frame truncated mid-payload ───────────────────────────────────────
    // Header announces 20 bytes of payload; only 5 actually arrive (a peer
    // that died mid-write, or an attacker probing the parser).
    {
        var short_wire: [9]u8 = undefined; // 4-byte header + 5-byte body, header claims 20
        std.mem.writeInt(u32, short_wire[0..4], 20, .little);
        @memcpy(short_wire[4..9], "hello");
        var r: std.Io.Reader = .fixed(&short_wire);
        if (framing.readFrame(&r, &frame_buf, .{})) |_| {
            unreachable;
        } else |err| switch (err) {
            error.EndOfStream => std.debug.print("truncated frame (20 announced, 5 delivered): EndOfStream (expected)\n", .{}),
            else => return err,
        }
    }

    // ── a frame exceeding a declared maximum, both directions ──────────────
    const tiny_limits = framing.Limits{ .max_frame = 16 };

    // Read side: header announces more than the caller's protocol cap allows,
    // even though the caller's own buffer is plenty large.
    {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, 1000, .little);
        var r: std.Io.Reader = .fixed(&hdr);
        if (framing.readFrame(&r, &frame_buf, tiny_limits)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.FrameTooLarge => std.debug.print("read side: announced 1000 > cap 16: FrameTooLarge (expected)\n", .{}),
            else => return err,
        }
    }

    // Write side, through the ALLOCATING envelope path: `writeFramed` JSON-
    // encodes first (an allocation) and only then checks the cap. The
    // interesting property is what this example's outer `DebugAllocator`
    // proves rather than prints: that scratch buffer is freed even though
    // the call returns an error, i.e. no leak on the reject path.
    {
        const big_note = "x" ** 64;
        var out: [8]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        if (Codec.writeFramed(.{ .status = .{ .ok = false, .note = big_note } }, gpa, &w, tiny_limits)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.FrameTooLarge => std.debug.print("write side: encoded envelope > cap 16: FrameTooLarge (expected), scratch freed\n", .{}),
            else => return err,
        }
    }

    // ── readFrameAlloc: the announced-length check runs BEFORE allocating ──
    // A 4 GiB announced length must never reach the allocator, let alone
    // succeed. If it ever did allocate before checking, the DebugAllocator
    // above would report a leak on the way out (nothing here would free it).
    {
        const huge_hdr = [_]u8{ 0xff, 0xff, 0xff, 0xff };
        var r: std.Io.Reader = .fixed(&huge_hdr);
        if (framing.readFrameAlloc(&r, gpa, .{})) |_| {
            unreachable;
        } else |err| switch (err) {
            error.FrameTooLarge => std.debug.print("readFrameAlloc: 4 GiB announced: FrameTooLarge before allocating (expected)\n", .{}),
            else => return err,
        }
    }
}
