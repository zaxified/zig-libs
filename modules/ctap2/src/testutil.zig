// SPDX-License-Identifier: MIT
//! Test-only helpers: a scripted transport and a scripted random source.

const std = @import("std");
const framing = @import("framing.zig");

/// Plays back canned responses and records every request it is sent.
pub const ScriptTransport = struct {
    allocator: std.mem.Allocator,
    responses: []const []const u8,
    idx: usize = 0,
    requests: std.ArrayList([]u8) = .empty,
    /// When set, every transaction fails with `TransportFailed`.
    fail: bool = false,

    pub fn init(allocator: std.mem.Allocator, responses: []const []const u8) ScriptTransport {
        return .{ .allocator = allocator, .responses = responses };
    }

    pub fn deinit(self: *ScriptTransport) void {
        for (self.requests.items) |r| self.allocator.free(r);
        self.requests.deinit(self.allocator);
    }

    pub fn transport(self: *ScriptTransport) framing.Transport {
        return .{ .ctx = self, .transactFn = transact };
    }

    fn transact(ctx: *anyopaque, request: []const u8, response: []u8) framing.TransportError!usize {
        const self: *ScriptTransport = @ptrCast(@alignCast(ctx));
        const copy = self.allocator.dupe(u8, request) catch return error.TransportFailed;
        self.requests.append(self.allocator, copy) catch {
            self.allocator.free(copy);
            return error.TransportFailed;
        };
        if (self.fail or self.idx >= self.responses.len) return error.TransportFailed;
        const r = self.responses[self.idx];
        self.idx += 1;
        if (r.len > response.len) return error.ResponseBufferTooSmall;
        @memcpy(response[0..r.len], r);
        return r.len;
    }
};

/// A `std.Random` that hands out a fixed byte script (all-zero and flagged
/// once the script runs out).
pub const ScriptRandom = struct {
    bytes: []const u8,
    pos: usize = 0,
    overrun: bool = false,

    pub fn random(self: *ScriptRandom) std.Random {
        return std.Random.init(self, fill);
    }

    fn fill(self: *ScriptRandom, buf: []u8) void {
        for (buf) |*b| {
            if (self.pos < self.bytes.len) {
                b.* = self.bytes[self.pos];
                self.pos += 1;
            } else {
                b.* = 0;
                self.overrun = true;
            }
        }
    }

    pub fn consumedAll(self: *const ScriptRandom) bool {
        return !self.overrun and self.pos == self.bytes.len;
    }
};
