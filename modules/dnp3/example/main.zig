// SPDX-License-Identifier: MIT

//! What a DNP3 master does with `dnp3`: build a class-0 (all-static) READ
//! request application fragment, feed it to a live `outstation.Outstation`
//! answering for one analog input, and decode the response fragment back
//! down to the object header and the record it carries — a real request
//! round trip through the pure codec + stateful outstation, not just a
//! byte-for-byte encode/decode check.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const dnp3 = @import("dnp3");
const application = dnp3.application;
const objects = dnp3.objects;
const records = dnp3.records;
const outstation = dnp3.outstation;

pub fn main() !void {
    // dnp3 is allocation-free: every codec here is a pure function over
    // caller-owned byte slices, and the outstation's state is caller-owned
    // too (no allocator anywhere in the public API).
    var analog_inputs = [_]outstation.AnalogInput{
        .{ .value = 21.7, .static_variation = 5 }, // g30v5: 32-bit float, with flags
    };
    var event_storage: [4]outstation.Event = undefined;
    const db: outstation.Database = .{ .analog_inputs = &analog_inputs };
    var station: outstation.Outstation = .init(.{}, db, .init(&event_storage));

    // ── build a class-0 READ request, the way a master polling on scan
    //    interval does ──────────────────────────────────────────────────
    var req_buf: [16]u8 = undefined;
    const request = try application.buildRequest(0, .read, objects.g60.readClassHeader(.class0), &req_buf);
    std.debug.print("request: {d} bytes\n", .{request.len});

    var resp_buf: [256]u8 = undefined;
    const reply = (try station.handle(request, 0, &resp_buf)) orelse return error.NoReply;
    std.debug.print("response: {d} bytes, confirm_requested={}\n", .{ reply.fragment.len, reply.confirm_requested });

    // ── decode the response back down: app header -> object header ->
    //    the analog-input record it carries ─────────────────────────────
    const app = try application.decodeResponseHeader(reply.fragment);
    std.debug.print("function={s} device_restart={}\n", .{ @tagName(app.header.function), app.header.iin.device_restart });

    const obj = try objects.decodeObjectHeader(app.rest);
    const layout = records.layoutOf(obj.header.group, obj.header.variation) orelse return error.UnknownLayout;
    const record = try records.decode(layout, .analog_input, app.rest[obj.consumed..]);
    std.debug.print("g{d}v{d} point[{d}] = {d:.1}\n", .{
        obj.header.group, obj.header.variation, obj.header.range.start_stop.start, record.value.analog_float,
    });

    // ── an undersized reply buffer is refused by name, not silently
    //    truncated ──────────────────────────────────────────────────────
    var tiny_buf: [1]u8 = undefined;
    _ = station.handle(request, 0, &tiny_buf) catch |err| switch (err) {
        error.BufferTooSmall => {
            std.debug.print("undersized reply buffer correctly rejected\n", .{});
            return;
        },
    };
    return error.ExpectedBufferTooSmall;
}
