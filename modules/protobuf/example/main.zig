// SPDX-License-Identifier: MIT

//! What a service does with `protobuf`: define a request message (with a
//! nested submessage and a repeated field) as a plain Zig struct, encode it
//! to wire bytes, decode those bytes back, and reject a truncated frame the
//! way a real receiver must — by name, not by falling through to a generic
//! failure.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling.

const std = @import("std");
const protobuf = @import("protobuf");

const Address = struct {
    city: []const u8 = "",
    zip: []const u8 = "",

    pub const pb_fields = .{
        .city = protobuf.Field{ .number = 1, .kind = .string },
        .zip = protobuf.Field{ .number = 2, .kind = .string },
    };
};

const CreateOrderRequest = struct {
    customer_id: i32 = 0,
    tags: []const []const u8 = &.{},
    ship_to: ?Address = null,

    pub const pb_fields = .{
        .customer_id = protobuf.Field{ .number = 1, .kind = .sint32 },
        .tags = protobuf.Field{ .number = 2, .kind = .string },
        .ship_to = protobuf.Field{ .number = 3, .kind = .message },
    };
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const req = CreateOrderRequest{
        .customer_id = 4711,
        .tags = &.{ "rush", "gift-wrap" },
        .ship_to = .{ .city = "Brno", .zip = "60200" },
    };

    const bytes = try protobuf.encodeAlloc(gpa, req, .{});
    defer gpa.free(bytes);
    std.debug.print("encoded {d} bytes\n", .{bytes.len});

    var decoded = try protobuf.decode(CreateOrderRequest, gpa, bytes, .{});
    defer decoded.deinit();
    std.debug.print("customer_id={d} tags={d} ship_to.city={s}\n", .{
        decoded.value.customer_id,
        decoded.value.tags.len,
        if (decoded.value.ship_to) |a| a.city else "(none)",
    });

    // A frame truncated mid-field must be rejected before any allocation is
    // sized from its claimed (now-unreliable) length — the module's whole
    // threat model. Handled by name, not folded into a generic error.
    const truncated = bytes[0 .. bytes.len - 3];
    _ = protobuf.decode(CreateOrderRequest, gpa, truncated, .{}) catch |err| switch (err) {
        error.Truncated => std.debug.print("rejected truncated frame ({d}/{d} bytes)\n", .{ truncated.len, bytes.len }),
        else => return err,
    };

    // A strict receiver: reject anything the schema doesn't describe rather
    // than silently forward it. Encode a message with an extra field the
    // strict schema below does not declare.
    const Wide = struct {
        customer_id: i32 = 0,
        secret_internal_note: []const u8 = "",
        pub const pb_fields = .{
            .customer_id = protobuf.Field{ .number = 1, .kind = .sint32 },
            .secret_internal_note = protobuf.Field{ .number = 99, .kind = .string },
        };
    };
    const Strict = struct {
        customer_id: i32 = 0,
        pub const pb_fields = .{
            .customer_id = protobuf.Field{ .number = 1, .kind = .sint32 },
        };
    };
    const wide_bytes = try protobuf.encodeAlloc(gpa, Wide{ .customer_id = 1, .secret_internal_note = "internal" }, .{});
    defer gpa.free(wide_bytes);
    _ = protobuf.decode(Strict, gpa, wide_bytes, .{ .reject_unknown_fields = true }) catch |err| switch (err) {
        error.UnknownField => std.debug.print("strict receiver rejected an undeclared field\n", .{}),
        else => return err,
    };
}
