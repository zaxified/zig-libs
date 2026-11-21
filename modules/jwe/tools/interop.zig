// SPDX-License-Identifier: MIT

//! Foreign check of the multi-recipient JWE JSON serialization (RFC 7516 section 7.2) against go-jose v4 (Go,
//! Apache-2.0, run as a black box; `tools/gojose/main.go` is our own small driver around its public API).
//!
//! Both directions, one shared key set (a 128-bit and a 256-bit AES KW key, a 128-bit AES-GCM KW key, an RSA-2048
//! key, a P-256 key, a PBES2 password):
//!   * ours to theirs: `jwe.encryptJsonRecipients` writes, for each of the four `enc` values with and without an
//!     `aad` member, a general document with seven recipients (A128KW, A256KW, A128GCMKW, RSA-OAEP, RSA-OAEP-256,
//!     ECDH-ES+A128KW, PBES2-HS256+A128KW), and, for each `enc`, one flattened document per `alg` (plus direct
//!     ECDH-ES). go-jose must open every recipient of every document with that recipient's key, to the plaintext.
//!   * theirs to ours: go-jose writes the same set (multi-recipient and flattened, with and without `aad`);
//!     `jwe.decryptJson` must open every recipient with that recipient's key, to the plaintext.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-jwe` runs it and `zig build check-interop` compiles it. Needs
//! `go` (>= 1.24) with go-jose v4.1.4 in the module cache (`GOPROXY=off`, nothing is downloaded). No network. Run from
//! the repository root; scratch files go to `.zig-cache/interop-jwe/`. Exit 0 = every opening agreed; 2 = no go.

const std = @import("std");
const jwe = @import("jwe");
const rsa = @import("rsa");

const work_dir = ".zig-cache/interop-jwe";
const go_dir = "modules/jwe/tools/gojose";

const password = "correct horse battery staple";
const aad_text = "additional authenticated data";
const b64url = std.base64.url_safe_no_pad;

const encs = [_]jwe.Enc{ .A128GCM, .A256GCM, .@"A128CBC-HS256", .@"A256CBC-HS512" };
/// The recipient slots shared with `gojose/main.go`.
const slot_algs = [_]jwe.Alg{ .A128KW, .A256KW, .A128GCMKW, .@"RSA-OAEP", .@"RSA-OAEP-256", .@"ECDH-ES+A128KW", .@"PBES2-HS256+A128KW", .@"ECDH-ES" };
const general_slots = [_]i64{ 0, 1, 2, 3, 4, 5, 6 };

const Keys = struct {
    sym: [3][]const u8,
    rsa_kp: rsa.KeyPair,
    ec: jwe.ecdhes.EphemeralKeyPair,

    fn recipient(self: *const Keys, slot: usize) jwe.JsonRecipient {
        return .{
            .key_alg = slot_algs[slot],
            .key = switch (slot) {
                0, 1, 2 => .{ .symmetric = self.sym[slot] },
                3, 4 => .{ .rsa_public = self.rsa_kp.public_key },
                5, 7 => .{ .ec_public = self.ec.public },
                else => .{ .password = password },
            },
            .opts = .{ .pbes2_iterations = 10_000 },
        };
    }

    fn decryptionKey(self: *const Keys, slot: usize) jwe.KeyMaterial {
        return switch (slot) {
            0, 1, 2 => .{ .symmetric = self.sym[slot] },
            3, 4 => .{ .rsa_private = &self.rsa_kp.secret_key },
            5, 7 => .{ .ec_private = &self.ec.private },
            else => .{ .password = password },
        };
    }
};

const Line = struct {
    name: []const u8,
    plaintext: []const u8,
    doc: []const u8,
    slots: []const i64,
};

fn run(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8) !std.process.RunResult {
    return std.process.run(arena, io, .{ .argv = argv });
}

fn ok(r: std.process.RunResult) bool {
    return r.term == .exited and r.term.exited == 0;
}

fn jsonString(arena: std.mem.Allocator, value: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(value, .{}, &aw.writer);
    return aw.toOwnedSlice();
}

fn writeKeys(arena: std.mem.Allocator, io: std.Io, keys: *const Keys, path: []const u8) !void {
    var pem_buf: [rsa.max_private_pem_len]u8 = undefined;
    const pem = try keys.rsa_kp.secret_key.toPem(.pkcs1, &pem_buf);
    const coords = keys.ec.public.coordinates();
    var xb: [64]u8 = undefined;
    var yb: [64]u8 = undefined;
    var db: [64]u8 = undefined;
    const jwk = try jsonString(arena, .{
        .kty = "EC",
        .crv = "P-256",
        .x = b64url.Encoder.encode(&xb, coords.xSlice()),
        .y = b64url.Encoder.encode(&yb, coords.ySlice().?),
        .d = b64url.Encoder.encode(&db, &keys.ec.private.p256),
    });
    const json = try jsonString(arena, .{
        .a128kw = std.fmt.bytesToHex(keys.sym[0][0..16].*, .lower),
        .a256kw = std.fmt.bytesToHex(keys.sym[1][0..32].*, .lower),
        .a128gcmkw = std.fmt.bytesToHex(keys.sym[2][0..16].*, .lower),
        .password = password,
        .rsa_pem = pem,
        .ec = @as(std.json.Value, try std.json.parseFromSliceLeaky(std.json.Value, arena, jwk, .{})),
    });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = json });
}

/// Our documents, one JSON line each (`Line`), for go-jose to open.
fn writeOurs(arena: std.mem.Allocator, io: std.Io, keys: *const Keys, random: std.Random, path: []const u8) !usize {
    var out: std.ArrayList(u8) = .empty;
    var count: usize = 0;
    for (encs) |enc| {
        for ([_]?[]const u8{ null, aad_text }) |aad| {
            var recipients: [general_slots.len]jwe.JsonRecipient = undefined;
            for (general_slots, 0..) |s, i| recipients[i] = keys.recipient(@intCast(s));
            const name = try arena.print("general/{s}/{s}", .{ @tagName(enc), if (aad == null) "noaad" else "aad" });
            const pt = try arena.print("zig-libs to go-jose: {s}", .{name});
            const doc = try jwe.encryptJsonRecipients(arena, .general, enc, &recipients, pt, .{ .fixed_for_test = random }, .{ .aad = aad });
            try out.appendSlice(arena, try jsonString(arena, Line{ .name = name, .plaintext = pt, .doc = doc, .slots = &general_slots }));
            try out.append(arena, '\n');
            count += 1;
        }
        for (0..slot_algs.len) |slot| {
            const name = try arena.print("flattened/{s}/{s}", .{ @tagName(slot_algs[slot]), @tagName(enc) });
            const pt = try arena.print("zig-libs to go-jose: {s}", .{name});
            const one = [_]jwe.JsonRecipient{keys.recipient(slot)};
            const doc = try jwe.encryptJsonRecipients(arena, .flattened, enc, &one, pt, .{ .fixed_for_test = random }, .{});
            const slots = [_]i64{@intCast(slot)};
            try out.appendSlice(arena, try jsonString(arena, Line{ .name = name, .plaintext = pt, .doc = doc, .slots = &slots }));
            try out.append(arena, '\n');
            count += 1;
        }
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = out.items });
    return count;
}

/// `doc` (a general document) with its `recipients` cut down to the entry `pos`.
fn onlyRecipient(arena: std.mem.Allocator, doc: []const u8, pos: usize) ![]u8 {
    var root = try std.json.parseFromSliceLeaky(std.json.Value, arena, doc, .{});
    var one: std.json.Array = .init(arena);
    try one.append(root.object.get("recipients").?.array.items[pos]);
    try root.object.put(arena, "recipients", .{ .array = one });
    return jsonString(arena, root);
}

/// go-jose's documents opened by `decryptJson`, every recipient with its own key. Returns the failure count.
fn readTheirs(arena: std.mem.Allocator, io: std.Io, keys: *const Keys, path: []const u8) !usize {
    const text = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64 << 20));
    var failures: usize = 0;
    var openings: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (raw.len == 0) continue;
        const l = try std.json.parseFromSliceLeaky(Line, arena, raw, .{ .ignore_unknown_fields = true });
        for (l.slots, 0..) |s, pos| {
            openings += 1;
            const slot: usize = @intCast(s);
            // One CEK is shared by every recipient, so `decryptJson` on the whole document opens the first
            // recipient a key serves; each recipient is opened alone, in a document that carries only its entry.
            const doc = if (l.slots.len > 1) try onlyRecipient(arena, l.doc, pos) else l.doc;
            const pt = jwe.decryptJson(arena, keys.decryptionKey(slot), doc, .{}) catch |e| {
                std.debug.print("interop-jwe: go-jose to zig-libs {s} slot {d} ({s}): {s}\n", .{ l.name, slot, @tagName(slot_algs[slot]), @errorName(e) });
                failures += 1;
                continue;
            };
            if (!std.mem.eql(u8, pt, l.plaintext)) {
                std.debug.print("interop-jwe: go-jose to zig-libs {s} slot {d}: plaintext differs\n", .{ l.name, slot });
                failures += 1;
            }
        }
    }
    std.debug.print("interop-jwe: go-jose to zig-libs: {d} recipient openings, {d} failed\n", .{ openings, failures });
    return failures;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    try std.Io.Dir.cwd().createDirPath(io, work_dir);

    const ver = run(arena, io, &.{ "go", "version" }) catch {
        std.debug.print("interop-jwe: go not found\n", .{});
        return 2;
    };
    std.debug.print("interop-jwe: {s}", .{ver.stdout});

    const exe = work_dir ++ "/gojose";
    const build = try run(arena, io, &.{ "env", "-C", go_dir, "GOFLAGS=-mod=mod", "GOPROXY=off", "go", "build", "-o", "../../../../" ++ exe, "." });
    if (!ok(build)) {
        std.debug.print("interop-jwe: go build failed (is go-jose v4.1.4 in the module cache?)\n{s}\n", .{build.stderr});
        return 2;
    }

    var prng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x6a)));
    const random = prng.random();
    var sym: [3][]u8 = undefined;
    for (&sym, [_]usize{ 16, 32, 16 }) |*k, n| {
        k.* = try arena.alloc(u8, n);
        random.bytes(k.*);
    }
    var keys: Keys = .{ .sym = .{ sym[0], sym[1], sym[2] }, .rsa_kp = undefined, .ec = undefined };
    try rsa.generate(&keys.rsa_kp, random, 2048, 65537);
    jwe.ecdhes.generateEphemeral(&keys.ec, .p256, .{ .fixed_for_test = random });

    const keys_path = work_dir ++ "/keys.json";
    const ours_path = work_dir ++ "/ours.jsonl";
    const theirs_path = work_dir ++ "/theirs.jsonl";
    try writeKeys(arena, io, &keys, keys_path);

    var failures: usize = 0;

    const n_ours = try writeOurs(arena, io, &keys, random, ours_path);
    const dec = try run(arena, io, &.{ exe, "-mode", "decrypt", "-keys", keys_path, "-in", ours_path });
    std.debug.print("interop-jwe: zig-libs to go-jose ({d} documents): {s}", .{ n_ours, dec.stdout });
    if (!ok(dec)) {
        std.debug.print("{s}{s}", .{ dec.stdout, dec.stderr });
        failures += 1;
    }

    const enc = try run(arena, io, &.{ exe, "-mode", "encrypt", "-keys", keys_path, "-out", theirs_path });
    if (!ok(enc)) {
        std.debug.print("interop-jwe: go-jose encrypt failed: {s}\n", .{enc.stderr});
        return 1;
    }
    failures += try readTheirs(arena, io, &keys, theirs_path);

    return if (failures == 0) 0 else 1;
}
