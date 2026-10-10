// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over ssh's `testing.fuzz` harnesses (added
//! 2026-10-09). The harness bodies stay in the files whose private items they
//! drive (`messages.zig`, `transport.zig`, `connection.zig`, `userauth.zig`),
//! now generic over their source of choices (`fn(comptime S, *S, gpa)`), and
//! each file carries its own driver test and in-suite reach test. This file
//! holds what they share -- the reach counters, the corpus-replaying source
//! the driver feeds the byte-stream harnesses with -- and the one harness that
//! needs only public API: private-key loading (`HostKey.fromOpenSSH`,
//! `AuthKey.fromOpenSSH`) on raw and on damaged OpenSSH containers.
//!
//! Drivers: `SSH_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there); harness names `ssh-
//! readstring`, `ssh-readmpint`, `ssh-kexinit`, `ssh-readpacket`,
//! `ssh-session`, `ssh-userauth`, `ssh-keyload`, `ssh-pubkey`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const server = @import("server.zig");
const userauth = @import("userauth.zig");
const vectors = @import("hostkey_vectors.zig");

/// Reach counters for one harness: an enum of outcomes, `mark` in the
/// harness, `check` after the in-suite seeds.
pub fn Reach(comptime L: type) type {
    return struct {
        var counts: [@typeInfo(L).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: L) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reset() void {
            counts = @splat(0);
        }

        pub fn check(name: []const u8) !void {
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: {s}: label {t} never hit\n", .{ name, @as(L, @enumFromInt(i)) });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// The in-suite run: `seeds` seeds through the driver's own `Rng`, then the
/// reach check. `drive` is the same wrapper the driver test hands to `run`.
pub fn reachSeeds(comptime R: type, comptime name: []const u8, comptime drive: anytype, seeds: usize) !void {
    R.reset();
    for (0..seeds) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        drive(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("{s} seed {d}: {t}\n", .{ name, seed, err });
            return err;
        };
    }
    try R.check(name);
}

/// Run `harness` over `src`. A driver `Rng` is wrapped in a `CorpusRng` over
/// `entries` (the harness's own seed corpus); any other source (`Smith`, for a
/// replayed `--fuzz` input) is handed through untouched.
pub fn corpusDrive(comptime S: type, src: *S, gpa: std.mem.Allocator, entries: []const []const u8, comptime harness: anytype) anyerror!void {
    if (S == fuzz_driver.Rng) {
        var crng = CorpusRng.init(src.r, entries);
        return harness(CorpusRng, &crng, gpa);
    }
    return harness(S, src, gpa);
}

/// A source for harnesses whose every input is a sequence of `slice` draws
/// (length-prefixed octet strings: one frame, or a list of message payloads
/// ended by an empty one). Random octets never get past the first parse check
/// of a wire format, so a run either draws purely at random (1 in 4) or
/// replays one corpus entry, record by record, with some records damaged: 1-3
/// octets flipped or the record cut short. Corpus entries are in `Smith.slice`
/// framing (a little-endian u32 length, then the octets), as `testkit.fuzz`
/// builds them.
pub const CorpusRng = struct {
    r: std.Random,
    entries: []const []const u8,
    replay: bool,
    damage: bool,
    entry: []const u8,
    at: usize = 0,

    pub fn init(r: std.Random, entries: []const []const u8) CorpusRng {
        const replay = entries.len != 0 and r.uintLessThan(u8, 4) != 0;
        return .{
            .r = r,
            .entries = entries,
            .replay = replay,
            .damage = r.uintLessThan(u8, 4) != 0,
            .entry = if (replay) entries[r.uintLessThan(usize, entries.len)] else "",
        };
    }

    pub fn valueRangeAtMost(self: *CorpusRng, comptime T: type, at_least: T, at_most: T) T {
        return self.r.intRangeAtMost(T, at_least, at_most);
    }
    pub fn value(self: *CorpusRng, comptime T: type) T {
        return self.r.int(T);
    }
    pub fn bytes(self: *CorpusRng, buf: []u8) void {
        self.r.bytes(buf);
    }
    pub fn index(self: *CorpusRng, len: usize) usize {
        return self.r.uintLessThan(usize, len);
    }
    pub fn slice(self: *CorpusRng, buf: []u8) u32 {
        if (!self.replay) {
            const cap: usize = if (buf.len > 64 and self.r.boolean()) 64 else buf.len;
            const n = self.r.uintAtMost(usize, cap);
            self.r.bytes(buf[0..n]);
            return @intCast(n);
        }
        if (self.at + 4 > self.entry.len) return 0;
        const len: usize = std.mem.readInt(u32, self.entry[self.at..][0..4], .little);
        self.at += 4;
        const have = @min(len, self.entry.len - self.at);
        var n = @min(have, buf.len);
        @memcpy(buf[0..n], self.entry[self.at..][0..n]);
        self.at += have;
        if (self.damage and n > 0 and self.r.boolean()) {
            if (self.r.uintLessThan(u8, 4) == 0) {
                n = self.r.uintAtMost(usize, n);
            } else {
                var k = self.r.intRangeAtMost(u8, 1, 3);
                while (k > 0) : (k -= 1) {
                    buf[self.r.uintLessThan(usize, n)] ^= self.r.intRangeAtMost(u8, 1, 255);
                }
            }
        }
        return @intCast(n);
    }
};

/// A `Smith` whose first `slice` draw was already taken by the `testing.fuzz`
/// callback itself (so the callback's first draw is a faithful one, which
/// `check-fuzz-reach` looks for): `slice` hands that record out first, then
/// reads on from `inner`. The harness sees exactly the draws it always saw.
pub fn Primed(comptime S: type) type {
    return struct {
        inner: *S,
        first: []const u8,
        taken: bool = false,

        pub fn slice(self: *@This(), buf: []u8) u32 {
            if (self.taken) return self.inner.slice(buf);
            self.taken = true;
            const n = @min(buf.len, self.first.len);
            @memcpy(buf[0..n], self.first[0..n]);
            return @intCast(n);
        }
    };
}

/// `testing.fuzz`'s source for harnesses that draw a shape: the bytes come
/// FIRST, in one `slice` draw, and every choice is read from them by a cursor,
/// so each seed is its own input (`check-fuzz-reach`).
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
    /// What `Smith.slice` would have returned for this script: up to
    /// `buf.len` of the remaining script bytes, and their count.
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        // `Cursor.byte` cycles, so `at` may already be past the end.
        if (n == 0) return 0;
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

// ── private-key loading ─────────────────────────────────────────────────────
//
// `HostKey.fromOpenSSH` parses an attacker-influenced file (an authorized
// deployment's key, but also whatever a tool is pointed at): the PEM armour,
// the openssh-key-v1 container, then the key-type-specific body. Raw bytes
// stop at the armour check, so the harness has three shapes:
//
//   0   raw drawn bytes;
//   1-4 one of the module's fixtures, de-armoured, 0-3 octets of the CONTAINER
//       damaged, re-armoured as PEM so the damage reaches the container parser;
//   5-7 one fixture's text, cut short.
//
// Oracle: an intact fixture must load and its public blob must equal the
// fixture's `.pub`; whatever else happens must be an error or -- when the
// damage fell on bytes the format ignores (comment, padding) -- the SAME
// public key. A load that yields a different key is a failure. `AuthKey` is an
// alias of `HostKey` (userauth.zig), so both entry points are called and must
// agree. A bcrypt-encrypted fixture is not used: the module has none, and a
// round count is not something damage to three octets can raise.

pub const KeyLabel = enum { raw_rejected, damaged_rejected, damaged_loaded, intact_loaded };
pub const key_reach = Reach(KeyLabel);

const Fixture = struct { text: []const u8, pub_b64: []const u8 };
const fixtures = [_]Fixture{
    .{ .text = vectors.ed25519_key, .pub_b64 = vectors.ed25519_pub_b64 },
    .{ .text = vectors.ecdsa_p256_key, .pub_b64 = vectors.ecdsa_p256_pub_b64 },
    .{ .text = vectors.rsa_key, .pub_b64 = vectors.rsa_pub_b64 },
};

const pem_begin = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
const pem_end = "-----END OPENSSH PRIVATE KEY-----\n";

/// The fixture's decoded openssh-key-v1 container.
fn deArmour(text: []const u8, out: []u8) []u8 {
    const body_start = std.mem.indexOf(u8, text, "-----\n").? + "-----\n".len;
    const body_end = std.mem.indexOf(u8, text, "-----END").?;
    var b64: [8192]u8 = undefined;
    var n: usize = 0;
    for (text[body_start..body_end]) |c| {
        if (c == '\n') continue;
        b64[n] = c;
        n += 1;
    }
    const dec = std.base64.standard.Decoder;
    const len = dec.calcSizeForSlice(b64[0..n]) catch unreachable;
    dec.decode(out[0..len], b64[0..n]) catch unreachable;
    return out[0..len];
}

/// PEM-armour `bin` (70 columns) into `out`.
fn reArmour(bin: []const u8, out: []u8) []u8 {
    var b64: [8192]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, bin);
    var w: std.Io.Writer = .fixed(out);
    w.writeAll(pem_begin) catch unreachable;
    var at: usize = 0;
    while (at < enc.len) : (at += 70) {
        w.writeAll(enc[at..@min(enc.len, at + 70)]) catch unreachable;
        w.writeByte('\n') catch unreachable;
    }
    w.writeAll(pem_end) catch unreachable;
    return w.buffered();
}

/// Load `text` through both entry points; they must agree. On success,
/// `fx`'s public blob (when given) is compared with the loaded key's.
fn loadBoth(gpa: std.mem.Allocator, text: []const u8, fx: ?Fixture) anyerror!bool {
    var hk: server.HostKey = undefined;
    var ak: userauth.AuthKey = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hk));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ak));
    const a_ok = if (server.HostKey.fromOpenSSH(&hk, text, null)) |_| true else |_| false;
    const b_ok = if (userauth.AuthKey.fromOpenSSH(&ak, text, null)) |_| true else |_| false;
    if (a_ok != b_ok) return error.LoadersDisagree;
    if (!a_ok) return false;
    if (fx) |f| {
        const blob = try hk.publicBlob(gpa);
        defer gpa.free(blob);
        var pub_buf: [1024]u8 = undefined;
        const dec = std.base64.standard.Decoder;
        const want = pub_buf[0..try dec.calcSizeForSlice(f.pub_b64)];
        try dec.decode(want, f.pub_b64);
        if (!std.mem.eql(u8, want, blob)) return error.DamagedKeyLoadedAsAnotherKey;
    }
    return true;
}

pub fn keyLoadHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const shape = src.valueRangeAtMost(u8, 0, 7);
    if (shape == 0) {
        var raw: [2048]u8 = undefined;
        const n = src.slice(&raw);
        if (try loadBoth(gpa, raw[0..n], null)) return;
        key_reach.mark(.raw_rejected);
        return;
    }
    const pick = src.valueRangeAtMost(u8, 0, 5);
    const fx = fixtures[
        switch (pick) {
            0...2 => 0,
            3...4 => 1,
            else => 2,
        }
    ];

    var intact = true;
    var text_buf: [8192]u8 = undefined;
    var text: []const u8 = undefined;
    if (shape <= 4) {
        var orig_buf: [4096]u8 = undefined;
        var bin_buf: [4096]u8 = undefined;
        const orig = deArmour(fx.text, &orig_buf);
        const bin = bin_buf[0..orig.len];
        @memcpy(bin, orig);
        var k = src.valueRangeAtMost(u8, 0, 3);
        while (k > 0) : (k -= 1) {
            const pos = @as(usize, src.value(u16)) % bin.len;
            bin[pos] ^= src.valueRangeAtMost(u8, 1, 255);
        }
        intact = std.mem.eql(u8, bin, orig);
        text = reArmour(bin, &text_buf);
    } else {
        const cut = @as(usize, src.value(u16)) % (fx.text.len + 1);
        intact = cut == fx.text.len;
        text = fx.text[0..cut];
    }

    const loaded = try loadBoth(gpa, text, fx);
    if (intact) {
        if (!loaded) return error.IntactKeyRejected;
        key_reach.mark(.intact_loaded);
    } else if (loaded) {
        key_reach.mark(.damaged_loaded);
    } else {
        key_reach.mark(.damaged_rejected);
    }
}

fn fuzzKeyLoad(_: void, smith: *testing.Smith) !void {
    var script: [512]u8 = undefined;
    const n = smith.slice(&script);
    var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return keyLoadHarness(ScriptSource, &src, testing.allocator);
}

const keyload_seeds = [_][]const u8{
    testkit.fuzz.seedHex("010000"), // shape 1, ed25519, no damage: loads
    testkit.fuzz.seedHex("0100020010ff0020aa"), // ed25519, two octets damaged
    testkit.fuzz.seedHex("0502000100"), // rsa fixture cut short
    testkit.fuzz.seed(""),
};

test "fuzz: private-key loading never panics on raw or damaged OpenSSH containers" {
    try testing.fuzz({}, fuzzKeyLoad, .{ .corpus = &keyload_seeds });
}

test "fuzz driver: SSH_FUZZ (ssh-keyload)" {
    try fuzz_driver.run(keyLoadHarness, .{ .prefix = "SSH_FUZZ", .name = "ssh-keyload" });
}

test "fuzz harness: 300 key-loading seeds in every test run, and they get everywhere" {
    try reachSeeds(key_reach, "ssh-keyload", keyLoadHarness, 300);
}

test "HostKey.fromOpenSSH: an RSA container whose public e disagrees with the secret key is refused" {
    // Regression (SSH_FUZZ `ssh-keyload` seed 56422, 2026-10-09): only n was
    // cross-checked, so a public blob with e = 0x018101 instead of 65537
    // loaded as a host key whose own signatures do not verify under it.
    var bin_buf: [8192]u8 = undefined;
    const bin = deArmour(vectors.rsa_key, &bin_buf);
    const e_wire = [_]u8{ 0, 0, 0, 3, 0x01, 0x00, 0x01 };
    const at = std.mem.indexOf(u8, bin, "ssh-rsa").? + "ssh-rsa".len;
    try testing.expectEqualSlices(u8, &e_wire, bin[at..][0..e_wire.len]);
    bin[at + 5] = 0x81;
    var text_buf: [8192]u8 = undefined;
    const text = reArmour(bin, &text_buf);
    var hk: server.HostKey = undefined;
    try testing.expectError(error.InvalidPrivateKey, server.HostKey.fromOpenSSH(&hk, text, null));
    var ak: userauth.AuthKey = undefined;
    try testing.expectError(error.InvalidPrivateKey, userauth.AuthKey.fromOpenSSH(&ak, text, null));
}

// ── public keys and authorized_keys lines ───────────────────────────────────
//
// `keys.PublicKey.parse` sees the PEER's bytes (the server's `K_S` through
// `HostKeyInfo.publicKey`, a client's `publickey` blob); the `authorized_keys`
// parser sees a local file. Shapes:
//
//   0   raw drawn bytes as a blob;
//   1-3 a fixture blob (five key types), 0-3 octets damaged or cut short;
//   4-5 a fixture written as an `authorized_keys` line with drawn options
//       and comment octets, then 0-3 octets of the LINE damaged.
//
// Oracle: an intact fixture parses as its own type; anything that parses
// survives `writeAuthorizedKey` → `parseAuthorizedKeyLine` with the same blob
// and both fingerprints compute; nothing panics.

const keys = @import("keys.zig");

pub const PubLabel = enum { raw_rejected, intact_parsed, damaged_rejected, damaged_parsed, line_parsed, line_rejected };
pub const pub_reach = Reach(PubLabel);

const pub_fixtures = [_][]const u8{
    vectors.ed25519_pub_b64,    vectors.rsa_pub_b64,        vectors.ecdsa_p256_pub_b64,
    vectors.ecdsa_p384_pub_b64, vectors.ecdsa_p521_pub_b64,
};

fn roundTrip(key: keys.PublicKey) anyerror!void {
    var fs: [keys.fingerprint_sha256_len]u8 = undefined;
    _ = key.fingerprintSha256(&fs);
    var fm: [keys.fingerprint_md5_len]u8 = undefined;
    _ = key.fingerprintMd5(&fm);
    var line: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line);
    try keys.writeAuthorizedKey(&w, key, "c");
    var buf: [keys.max_blob_len]u8 = undefined;
    const again = try keys.parseAuthorizedKeyLine(w.buffered(), &buf);
    if (!again.key.eql(key)) return error.RoundTripChangedKey;
}

pub fn pubKeyHarness(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const shape = src.valueRangeAtMost(u8, 0, 5);
    if (shape == 0) {
        var raw: [keys.max_blob_len + 16]u8 = undefined;
        const n = src.slice(&raw);
        if (keys.PublicKey.parse(raw[0..n])) |k| return roundTrip(k) else |_| {}
        pub_reach.mark(.raw_rejected);
        return;
    }
    const fx = pub_fixtures[src.valueRangeAtMost(u8, 0, pub_fixtures.len - 1)];
    var orig_buf: [keys.max_blob_len]u8 = undefined;
    const dec = std.base64.standard.Decoder;
    const orig = orig_buf[0..try dec.calcSizeForSlice(fx)];
    try dec.decode(orig, fx);

    if (shape <= 3) {
        var bin_buf: [keys.max_blob_len]u8 = undefined;
        var bin: []u8 = bin_buf[0..orig.len];
        @memcpy(bin, orig);
        if (src.value(bool)) {
            bin = bin[0 .. @as(usize, src.value(u16)) % (bin.len + 1)];
        } else {
            var k = src.valueRangeAtMost(u8, 0, 3);
            while (k > 0) : (k -= 1) bin[@as(usize, src.value(u16)) % bin.len] ^= src.valueRangeAtMost(u8, 1, 255);
        }
        const intact = std.mem.eql(u8, bin, orig);
        if (keys.PublicKey.parse(bin)) |key| {
            try roundTrip(key);
            if (intact) pub_reach.mark(.intact_parsed) else pub_reach.mark(.damaged_parsed);
        } else |_| {
            if (intact) return error.IntactKeyRejected;
            pub_reach.mark(.damaged_rejected);
        }
        return;
    }

    var opts: [48]u8 = undefined;
    const on = src.slice(&opts);
    var comment: [24]u8 = undefined;
    const cn = src.slice(&comment);
    var line_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line_buf);
    if (on != 0) {
        try w.writeAll(opts[0..on]);
        try w.writeByte(' ');
    }
    try keys.writeAuthorizedKey(&w, try keys.PublicKey.parse(orig), comment[0..cn]);
    const line = line_buf[0..w.end];
    var k = src.valueRangeAtMost(u8, 0, 3);
    while (k > 0) : (k -= 1) line[@as(usize, src.value(u16)) % line.len] ^= src.valueRangeAtMost(u8, 1, 255);
    var buf: [keys.max_blob_len]u8 = undefined;
    if (keys.parseAuthorizedKeyLine(line, &buf)) |entry| {
        var it = entry.optionIterator();
        while (it.next()) |_| {}
        try roundTrip(entry.key);
        pub_reach.mark(.line_parsed);
    } else |_| pub_reach.mark(.line_rejected);
    var lines = keys.AuthorizedKeysIterator.init(line);
    while (lines.next(&buf)) |entry| try roundTrip(entry.key);
}

fn fuzzPubKey(_: void, smith: *testing.Smith) !void {
    var script: [512]u8 = undefined;
    const n = smith.slice(&script);
    var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
    return pubKeyHarness(ScriptSource, &src, testing.allocator);
}

const pubkey_seeds = [_][]const u8{
    testkit.fuzz.seedHex("010000"), // fixture 0 intact
    testkit.fuzz.seedHex("0104000200100ff0"), // p521 blob, two octets damaged
    testkit.fuzz.seedHex("04020000"), // ecdsa-p256 as a bare line
    testkit.fuzz.seed(""),
};

test "fuzz: public-key blobs and authorized_keys lines never panic" {
    try testing.fuzz({}, fuzzPubKey, .{ .corpus = &pubkey_seeds });
}

test "fuzz driver: SSH_FUZZ (ssh-pubkey)" {
    try fuzz_driver.run(pubKeyHarness, .{ .prefix = "SSH_FUZZ", .name = "ssh-pubkey" });
}

test "fuzz harness: 300 public-key seeds in every test run, and they get everywhere" {
    try reachSeeds(pub_reach, "ssh-pubkey", pubKeyHarness, 300);
}
