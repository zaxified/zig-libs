// SPDX-License-Identifier: MIT

//! What a FIDO2 platform does with `ctap2`: read an authenticator's GetInfo,
//! pick a PIN/UV auth protocol, check the PIN retry counter, and exchange a
//! PIN for a `pinUvAuthToken` with permissions -- then use the token to
//! authenticate a command. The authenticator here is a small in-process
//! simulation behind the `Transport` interface (there is no USB or NFC device
//! on this machine and the module does no device I/O anyway); it speaks real
//! CTAP2 bytes, so the platform code below is exactly what runs against a
//! device with a HID `Transport` under it.
//!
//! The simulated authenticator holds a PIN ("1234"), a retry counter, and a
//! fixed token. All key material below is SYNTHETIC: fixed byte patterns, not
//! entropy. A real platform passes a CSPRNG-backed `std.Random`.
//!
//! Built against the PUBLISHED module (`@import("ctap2")` and nothing else --
//! `cbor` and `ctap2pin` are re-exported by it).

const std = @import("std");
const ctap2 = @import("ctap2");
const cbor = ctap2.cbor;
const ctap2pin = ctap2.ctap2pin;

/// An authenticator that speaks protocol Two only.
const Authenticator = struct {
    allocator: std.mem.Allocator,
    scalar: [32]u8 = @splat(0x33), // synthetic key-agreement private key
    stored_pin_hash: [16]u8,
    token: [32]u8 = @splat(0xA5),
    retries: u32 = 8,

    fn init(allocator: std.mem.Allocator, pin: []const u8) Authenticator {
        return .{ .allocator = allocator, .stored_pin_hash = ctap2.clientpin.pinHash(pin) };
    }

    fn transport(self: *Authenticator) ctap2.Transport {
        return .{ .ctx = self, .transactFn = transact };
    }

    fn transact(ctx: *anyopaque, request: []const u8, response: []u8) ctap2.TransportError!usize {
        const self: *Authenticator = @ptrCast(@alignCast(ctx));
        return self.handle(request, response) catch error.TransportFailed;
    }

    fn reply(response: []u8, status: u8, body: ?[]const u8) usize {
        response[0] = status;
        if (body) |b| @memcpy(response[1..][0..b.len], b);
        return 1 + if (body) |b| b.len else 0;
    }

    fn handle(self: *Authenticator, request: []const u8, response: []u8) !usize {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const pub_key = try ctap2pin.publicKeyFromScalar(self.scalar);

        if (request[0] == 0x04) { // authenticatorGetInfo
            const opts = [_]cbor.MapEntry{
                .{ .key = .{ .text = "clientPin" }, .value = .{ .bool = true } },
                .{ .key = .{ .text = "pinUvAuthToken" }, .value = .{ .bool = true } },
            };
            const entries = [_]cbor.MapEntry{
                .{ .key = .{ .uint = 1 }, .value = .{ .array = &.{.{ .text = "FIDO_2_1" }} } },
                .{ .key = .{ .uint = 3 }, .value = .{ .bytes = &([_]u8{0x11} ** 16) } },
                .{ .key = .{ .uint = 4 }, .value = .{ .map = &opts } },
                .{ .key = .{ .uint = 6 }, .value = .{ .array = &.{.{ .uint = 2 }} } },
                .{ .key = .{ .uint = 0x0D }, .value = .{ .uint = 4 } },
            };
            return reply(response, 0, try cbor.encode(a, .{ .map = &entries }, .{ .canonical = true }));
        }

        // authenticatorClientPIN
        const req = (try cbor.decode(a, request[1..], .{})).map;
        var sub: u64 = 0;
        var key_agreement: ?cbor.Value = null;
        var pin_hash_enc: []const u8 = "";
        for (req) |e| switch (e.key.uint) {
            2 => sub = e.value.uint,
            3 => key_agreement = e.value,
            6 => pin_hash_enc = e.value.bytes,
            else => {},
        };
        switch (sub) {
            0x01 => {
                const e = [_]cbor.MapEntry{.{ .key = .{ .uint = 3 }, .value = .{ .uint = self.retries } }};
                return reply(response, 0, try cbor.encode(a, .{ .map = &e }, .{}));
            },
            0x02 => {
                const cose = [_]cbor.MapEntry{
                    .{ .key = cbor.Value.fromI64(1), .value = cbor.Value.fromI64(2) },
                    .{ .key = cbor.Value.fromI64(3), .value = cbor.Value.fromI64(-25) },
                    .{ .key = cbor.Value.fromI64(-1), .value = cbor.Value.fromI64(1) },
                    .{ .key = cbor.Value.fromI64(-2), .value = .{ .bytes = &pub_key.x } },
                    .{ .key = cbor.Value.fromI64(-3), .value = .{ .bytes = &pub_key.y } },
                };
                const e = [_]cbor.MapEntry{.{ .key = .{ .uint = 1 }, .value = .{ .map = &cose } }};
                return reply(response, 0, try cbor.encode(a, .{ .map = &e }, .{ .canonical = true }));
            },
            0x05, 0x09 => {
                if (self.retries == 0) return reply(response, 0x32, null); // PIN_BLOCKED
                const ec2 = (try cbor.cose.parseKey(key_agreement.?)).ec2;
                const peer: ctap2pin.PublicKey = .{ .x = ec2.x[0..32].*, .y = ec2.y[0..32].* };
                const secret = (try ctap2pin.Two.encapsulate(self.scalar, peer)).shared_secret;
                self.retries -= 1;
                var got: [16]u8 = undefined;
                try ctap2pin.Two.decrypt(secret, &got, pin_hash_enc);
                if (!std.crypto.timing_safe.eql([16]u8, got, self.stored_pin_hash))
                    return reply(response, 0x31, null); // PIN_INVALID
                self.retries = 8;
                var ct: [48]u8 = undefined;
                try ctap2pin.Two.encrypt(secret, @splat(0x77), &ct, &self.token);
                const e = [_]cbor.MapEntry{.{ .key = .{ .uint = 2 }, .value = .{ .bytes = &ct } }};
                return reply(response, 0, try cbor.encode(a, .{ .map = &e }, .{}));
            },
            else => return reply(response, 0x3E, null), // INVALID_SUBCOMMAND
        }
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() != .ok) @panic("leak");
    const gpa = da.allocator();

    var auth = Authenticator.init(gpa, "1234");
    const transport = auth.transport();

    // 1. GetInfo: which protocol, what PIN policy.
    const info = try ctap2.getinfo.get(gpa, transport, 1200);
    std.debug.print("authenticator: FIDO_2_1={}, clientPin={?}, protocol={s}, minPINLength={d}\n", .{
        info.versions.fido_2_1,
        info.pinState(),
        @tagName(info.preferredProtocol().?),
        info.effectiveMinPinLength(),
    });

    // 2. A client bound to the transport. The random source is synthetic here.
    var prng = std.Random.DefaultPrng.init(0x5eed);
    var client = ctap2.Client.fromInfo(gpa, transport, prng.random(), info).?;

    const before = try client.getPinRetries();
    std.debug.print("PIN retries before: {d}\n", .{before.retries});

    // 3. A wrong PIN is a typed error and costs one retry.
    if (client.getPinUvAuthTokenUsingPin("0000", .{ .mc = true, .ga = true }, "example.com")) |_| {
        return error.WrongPinAccepted;
    } else |err| switch (err) {
        error.PinInvalid => std.debug.print("wrong PIN: error.PinInvalid, retries now {d}\n", .{(try client.getPinRetries()).retries}),
        else => return err,
    }

    // 4. The right PIN yields a token; use it to authenticate a command.
    var token = try client.getPinUvAuthTokenUsingPin("1234", .{ .mc = true, .ga = true }, "example.com");
    defer token.deinit(); // wipes the token
    const client_data_hash: [32]u8 = @splat(0xCD);
    const param = token.authenticate(&client_data_hash);
    std.debug.print("token: {d} bytes; pinUvAuthParam over clientDataHash: {x}\n", .{ token.len, param.slice() });
    const expected_token: [32]u8 = @splat(0xA5);
    if (!std.mem.eql(u8, token.slice(), &expected_token)) return error.WrongToken;

    // 5. Validation happens before any I/O: this PIN never leaves the process.
    if (client.setPin("abc")) |_| return error.ShortPinAccepted else |err| {
        std.debug.print("new PIN \"abc\": error.{s} (nothing sent)\n", .{@errorName(err)});
    }
}
