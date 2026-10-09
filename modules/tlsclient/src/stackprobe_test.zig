// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for the client-certificate signature
//! (`Client.signCertificateVerify`, all three key types) and for the handshake
//! (`Client.initInto`: a ServerHello alone, and a full server flight that
//! returns an established session — its application secrets must stay in the
//! `Client` only). Kept in the module per `CONVENTIONS.md` §9.
//!
//! Method as `acme`'s probe: paint a stack window below the probe, run the
//! call `PAD` bytes deeper, snapshot the window and look for secrets.
//! ReleaseFast / ReleaseSmall only — Debug and ReleaseSafe fill `undefined`
//! with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles are every 16-byte window of every image a secret is held in:
//! - ECDSA P-256 / P-384: `d`, and the nonce `k` solved from the signature
//!   the call produced (`k = s⁻¹·(e + r·d)`), `k⁻¹`, `r·d`, `e + r·d`;
//! - Ed25519: the seed, the clamped and unclamped scalar, the nonce prefix and
//!   the nonce (`SHA-512(prefix ‖ M)`, raw and reduced).
//! Windows with fewer than 8 distinct bytes are skipped.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks a secret in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const Client = @import("Client.zig");

const PrivateKey = Client.ClientAuth.PrivateKey;
const Ed = std.crypto.ecc.Edwards25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Es256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Es384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const WINDOW = 512 * 1024; // deeper than `burn.init_burn`
const LEAK = 32;
const W = 16; // needle window

/// Set `true` to print every call's residue and dirty depth (sizes a burn).
const verbose = false;

// ── needle set ──────────────────────────────────────────────────────────────

const max_windows = 8192;

const Needles = struct {
    win: [max_windows]u128 = undefined,
    owner: [max_windows]u8 = undefined,
    len: usize = 0,
    names: [32][]const u8 = undefined,
    n_names: usize = 0,

    fn addImage(self: *Needles, name: []const u8, image: []const u8) void {
        const id: u8 = @intCast(self.lookupName(name));
        var i: usize = 0;
        while (i + W <= image.len) : (i += 1) {
            if (distinct(image[i..][0..W]) < 8) continue;
            self.win[self.len] = std.mem.readInt(u128, image[i..][0..W], .little);
            self.owner[self.len] = id;
            self.len += 1;
        }
    }

    /// `image` and its byte reversal.
    fn addBoth(self: *Needles, name: []const u8, image: []const u8) void {
        self.addImage(name, image);
        var r: [128]u8 = undefined;
        @memcpy(r[0..image.len], image);
        std.mem.reverse(u8, r[0..image.len]);
        self.addImage(name, r[0..image.len]);
    }

    fn distinct(w: *const [W]u8) usize {
        var seen: [256]bool = @splat(false);
        var c: usize = 0;
        for (w) |b| {
            if (!seen[b]) c += 1;
            seen[b] = true;
        }
        return c;
    }

    fn lookupName(self: *Needles, name: []const u8) usize {
        for (self.names[0..self.n_names], 0..) |n, i| if (std.mem.eql(u8, n, name)) return i;
        self.names[self.n_names] = name;
        self.n_names += 1;
        return self.n_names - 1;
    }

    fn addScalar(self: *Needles, name: []const u8, s: anytype) void {
        self.addBoth(name, &s.toBytes(.big));
        self.addImage(name, std.mem.asBytes(&s));
    }

    fn sort(self: *Needles) void {
        const Ctx = struct {
            n: *Needles,
            pub fn lessThan(c: @This(), a: usize, b: usize) bool {
                return c.n.win[a] < c.n.win[b];
            }
            pub fn swap(c: @This(), a: usize, b: usize) void {
                std.mem.swap(u128, &c.n.win[a], &c.n.win[b]);
                std.mem.swap(u8, &c.n.owner[a], &c.n.owner[b]);
            }
        };
        std.sort.pdqContext(0, self.len, Ctx{ .n = self });
    }

    fn find(self: *const Needles, v: u128) ?u8 {
        var lo: usize = 0;
        var hi: usize = self.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (self.win[mid] < v) lo = mid + 1 else hi = mid;
        }
        return if (lo < self.len and self.win[lo] == v) self.owner[lo] else null;
    }
};

const Hits = [32]usize;

// ── the measured region ─────────────────────────────────────────────────────
//
// The region is addressed directly, below a fixed distance (`PAD`) under the
// probe's own stack position, and the measured call runs under a `PAD`-deep
// frame (`shim`), so its frames start inside the region. `paint` and
// `snapshot` run at the probe's own depth with frames far smaller than `PAD`:
// no instrument frame overlaps the region, so even the call's shallowest
// frames (a wrapper's by-value copies) are seen.
const PAD = 2048;

var region_lo: usize = 0;
var region_hi: usize = 0;
var snap: [WINDOW]u8 = undefined;

noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe, so its frames lie inside the
/// region. `pad` is touched after the call too, so it cannot be a tail call.
noinline fn shim(call: *const fn () void) void {
    var pad: [PAD]u8 = undefined;
    std.mem.doNotOptimizeAway(&pad);
    call();
    std.mem.doNotOptimizeAway(&pad);
}

noinline fn snapshot() void {
    const p: [*]const volatile u8 = @ptrFromInt(region_lo);
    for (&snap, 0..) |*d, i| d.* = p[i];
}

var hit_min_depth: usize = 0;
var hit_max_depth: usize = 0;

fn scan(needles: *const Needles) Hits {
    var hits: Hits = @splat(0);
    hit_min_depth = 0;
    hit_max_depth = 0;
    var skip_until: usize = 0;
    var i: usize = 0;
    while (i + W <= WINDOW) : (i += 1) {
        if (i < skip_until) continue;
        if (needles.find(std.mem.readInt(u128, snap[i..][0..W], .little))) |id| {
            hits[id] += 1;
            const d = WINDOW - i;
            if (hit_min_depth == 0 or d < hit_min_depth) hit_min_depth = d;
            if (d > hit_max_depth) hit_max_depth = d;
            skip_until = i + W;
        }
    }
    return hits;
}

fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks a secret in a stack local and returns.
var leak_src: [LEAK]u8 = undefined;
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..][0..LEAK].* = leak_src;
    std.mem.doNotOptimizeAway(&local);
}

/// Zero the callee-saved registers before a measured call: they still hold
/// the TEST's values — needles it just computed — and the call's prologue
/// spills them into its frame, where the scan credits them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// `inline`: as its own frame it ran the call deeper than the region top
/// `runProbe` computed (acme, 2026-10-08).
inline fn measure(call: *const fn () void, n: *const Needles) Hits {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    return scan(n);
}

fn runProbe(label: []const u8, call: *const fn () void, n: *const Needles) !usize {
    region_hi = stackHere() - PAD;
    region_lo = region_hi - WINDOW;

    const neg = measure(callInnocent, n);
    const pos = measure(callLeaky, n);

    var total: Hits = @splat(0);
    var shallowest: usize = 0;
    var deepest: usize = 0;
    for (0..5) |_| {
        for (&total, measure(call, n)) |*t, x| t.* += x;
        if (hit_min_depth != 0 and (shallowest == 0 or hit_min_depth < shallowest)) shallowest = hit_min_depth;
        if (hit_max_depth > deepest) deepest = hit_max_depth;
    }
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
    const depth = dirtyDepth();

    var sum: usize = 0;
    for (total) |h| sum += h;
    var neg_sum: usize = 0;
    for (neg) |h| neg_sum += h;
    var pos_sum: usize = 0;
    for (pos) |h| pos_sum += h;
    if (verbose or sum != 0 or neg_sum != 0 or pos_sum == 0) {
        std.debug.print("\n=== STACKPROBE tlsclient: {s} ({t}, window {d} KiB): NEG={d} POS={d} dirty={d} B ===\n", .{ label, builtin.mode, WINDOW / 1024, neg_sum, pos_sum, depth });
        for (n.names[0..n.n_names], 0..) |name, i| {
            if (total[i] != 0) std.debug.print("    RESIDUE {s:<14} {d} (5 calls)\n", .{ name, total[i] });
        }
        if (sum != 0) std.debug.print("    hits {d}..{d} B below the region top\n", .{ shallowest, deepest });
    }
    try std.testing.expectEqual(@as(usize, 0), neg_sum);
    try std.testing.expect(pos_sum >= 1); // the scan can see a parked secret
    return sum;
}

fn skipUnlessOptimized() !void {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
}

// ── needles ─────────────────────────────────────────────────────────────────

/// ECDSA needles for a signature `der` over `msg` made with the big-endian
/// scalar `d_bytes` (`Scheme` = std's `EcdsaP256Sha256` over `Curve`/`Hash`, or
/// the P-384 one).
fn ecdsaNeedles(comptime Scheme: type, comptime Curve: type, comptime Hash: type, n: *Needles, d_bytes: []const u8, msg: []const u8, der: []const u8) !void {
    const S = Curve.scalar.Scalar;
    const L = Curve.scalar.encoded_length;
    const sig = try Scheme.Signature.fromDer(der);
    var h: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &h, .{});
    const e = if (h.len >= 48) blk: {
        var xs: [64]u8 = @splat(0);
        @memcpy(xs[64 - h.len ..], &h);
        break :blk S.fromBytes64(xs, .big);
    } else blk: {
        var xs: [48]u8 = @splat(0);
        @memcpy(xs[48 - h.len ..], &h);
        break :blk S.fromBytes48(xs, .big);
    };
    const d = try S.fromBytes(d_bytes[0..L].*, .big);
    const r = try S.fromBytes(sig.r, .big);
    const s = try S.fromBytes(sig.s, .big);
    const rd = r.mul(d);
    const erd = e.add(rd);
    const k = s.invert().mul(erd);
    n.addScalar("d", d);
    n.addScalar("k", k);
    n.addScalar("k^-1", k.invert());
    n.addScalar("r*d", rd);
    n.addScalar("e+r*d", erd);
}

/// std signs without noise: nonce = reduce64(SHA-512(prefix ‖ msg)).
fn ed25519Needles(n: *Needles, seed: [32]u8, msg: []const u8) void {
    n.addBoth("seed", &seed);
    var az: [64]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    n.addBoth("a (unclamped)", az[0..32]);
    var a = az[0..32].*;
    Ed.scalar.clamp(&a);
    n.addBoth("a", &a);
    n.addBoth("prefix", az[32..64]);
    var h = Sha512.init(.{});
    h.update(az[32..64]);
    h.update(msg);
    var nonce64: [64]u8 = undefined;
    h.final(&nonce64);
    n.addBoth("nonce64", &nonce64);
    n.addBoth("r", &Ed.scalar.reduce64(nonce64));
}

// ── the probed call (`noinline`, the key read from static memory) ───────────

/// The caller's own storage for the key, as `ClientAuth.key` points at it.
var cur_key: PrivateKey = undefined;
var sig_buf: [160]u8 = undefined;
var sig_sink: []const u8 = &.{};

/// TLS 1.3 CertificateVerify content shape: 64 spaces, the context string, a
/// zero byte, the transcript hash (RFC 8446 §4.4.3).
const signed_msg = "\x20" ** 64 ++ "TLS 1.3, client CertificateVerify\x00" ++ "\x5a" ** 48;

noinline fn callSign() void {
    sig_sink = Client.signCertificateVerify(&sig_buf, &cur_key, signed_msg) catch unreachable;
    std.mem.doNotOptimizeAway(sig_sink.ptr);
}

fn caseSeed(comptime len: usize, i: u8) [len]u8 {
    var out: [64]u8 = undefined;
    Sha512.hash(&[_]u8{ 't', 'l', 's', '-', 's', 'e', 'e', 'd', i }, &out, .{});
    return out[0..len].*;
}

test "STACKPROBE: no key or nonce residue on the dead stack after the client CertificateVerify signature" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    for (0..2) |ci| {
        const i: u8 = @intCast(ci);
        {
            cur_key = .{ .ecdsa_secp256r1_sha256 = caseSeed(32, i) };
            leak_src = cur_key.ecdsa_secp256r1_sha256;
            callSign();
            var n: Needles = .{};
            try ecdsaNeedles(Es256, std.crypto.ecc.P256, Sha256, &n, &cur_key.ecdsa_secp256r1_sha256, signed_msg, sig_sink);
            n.sort();
            bad += try runProbe("signCertificateVerify P-256", callSign, &n);
        }
        {
            cur_key = .{ .ecdsa_secp384r1_sha384 = caseSeed(48, 0x10 + i) };
            leak_src = cur_key.ecdsa_secp384r1_sha384[0..LEAK].*;
            callSign();
            var n: Needles = .{};
            try ecdsaNeedles(Es384, std.crypto.ecc.P384, Sha384, &n, &cur_key.ecdsa_secp384r1_sha384, signed_msg, sig_sink);
            n.sort();
            bad += try runProbe("signCertificateVerify P-384", callSign, &n);
        }
        {
            cur_key = .{ .ed25519 = caseSeed(32, 0x20 + i) };
            leak_src = cur_key.ed25519;
            var n: Needles = .{};
            ed25519Needles(&n, cur_key.ed25519, signed_msg);
            n.sort();
            bad += try runProbe("signCertificateVerify Ed25519", callSign, &n);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

// ── the ECDHE key exchange and the handshake key schedule ───────────────────
//
// `Client.init` is driven with a canned server flight: one TLS record holding
// a ServerHello that selects one group, with a server key share built from a
// fixed server secret. `init` derives the shared secret and the handshake
// secrets on reading it, then fails reading the next record
// (`TlsConnectionTruncated`) — after the key exchange, which is the point.
// Application traffic secrets need a full server flight: out of scope.
//
// ⛔ A probe that never reaches the code finds 0 for the wrong reason: the
// reach check runs `init` once with `ssl_key_log` and requires the server
// handshake traffic secret the probe recomputed to be in the log.

const tls = std.crypto.tls;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const X25519 = std.crypto.dh.X25519;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const Sha3_512 = std.crypto.hash.sha3.Sha3_512;
const Hkdf = std.crypto.kdf.hkdf.Hkdf;
const Hmac = std.crypto.auth.hmac.sha2;
const Es256Pair = Es256.KeyPair;
const Es384Pair = Es384.KeyPair;

// ── API adapter: the only part that changes when the fix lands ──────────────

var kex_entropy: [Client.Options.entropy_len]u8 = undefined;
var in_buf: [Client.min_buffer_len]u8 = undefined;
var in_len: usize = 0;
var out_buf: [8192]u8 = undefined;
var read_buf: [Client.min_buffer_len]u8 = undefined;
var write_buf: [Client.min_buffer_len]u8 = undefined;
var in_reader: Reader = undefined;
var out_writer: Writer = undefined;
var init_err: ?anyerror = null;
var log_buf: [4096]u8 = undefined;
var log_writer: Writer = undefined;
var key_log: Client.SslKeyLog = undefined;
var use_key_log = false;
/// The established session lives here, off the stack (a full flight only).
var client_sink: Client = undefined;

noinline fn callInit() void {
    in_reader = Reader.fixed(&in_buf);
    in_reader.end = in_len;
    out_writer = Writer.fixed(&out_buf);
    const opts: Client.Options = .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &write_buf,
        .read_buffer = &read_buf,
        .entropy = &kex_entropy,
        .realtime_now = .{ .nanoseconds = 0 },
        .ssl_key_log = if (use_key_log) &key_log else null,
    };
    init_err = null;
    Client.initInto(&client_sink, &in_reader, &out_writer, opts) catch |e| {
        init_err = e;
    };
}

// ── the client's ephemeral keys, recomputed from the entropy ────────────────

const Keys = struct {
    mlkem: MLKem768.KeyPair,
    p256: Es256Pair,
    p384: Es384Pair,
    x25519: X25519.KeyPair,
};
var keys: Keys = undefined;

/// `len` bytes derived from (`tag`, `ci`) by hash — never `@splat`, which the
/// distinct-bytes filter would skip.
fn derive(comptime tag: []const u8, ci: u8, comptime len: usize) [len]u8 {
    var out: [(len + 63) / 64 * 64]u8 = undefined;
    var i: usize = 0;
    while (i * 64 < out.len) : (i += 1) {
        Sha512.hash(tag ++ &[_]u8{ ci, @intCast(i) }, out[i * 64 ..][0..64], .{});
    }
    return out[0..len].*;
}

fn putBytes(p: *usize, bytes: []const u8) void {
    @memcpy(in_buf[p.*..][0..bytes.len], bytes);
    p.* += bytes.len;
}

fn putInt(comptime T: type, p: *usize, v: T) void {
    std.mem.writeInt(T, in_buf[p.*..][0..@sizeOf(T)], v, .big);
    p.* += @sizeOf(T);
}

/// One record: a TLS 1.3 ServerHello selecting `suite`, `group` and `share`.
fn buildFlight(ci: u8, group: tls.NamedGroup, suite: tls.CipherSuite, share: []const u8) void {
    var p: usize = 5;
    in_buf[0] = 0x16;
    in_buf[1] = 3;
    in_buf[2] = 3;
    in_buf[p] = 2; // server_hello
    p += 4; // type + u24 length, patched below
    putInt(u16, &p, 0x0303);
    putBytes(&p, &derive("tls-server-random", ci, 32));
    in_buf[p] = 32;
    p += 1;
    putBytes(&p, kex_entropy[32..64]); // legacy_session_id echo
    putInt(u16, &p, @intFromEnum(suite));
    in_buf[p] = 0; // legacy_compression_method
    p += 1;
    putInt(u16, &p, @intCast(6 + 4 + 4 + share.len)); // extensions
    putInt(u16, &p, @intFromEnum(tls.ExtensionType.supported_versions));
    putInt(u16, &p, 2);
    putInt(u16, &p, 0x0304);
    putInt(u16, &p, @intFromEnum(tls.ExtensionType.key_share));
    putInt(u16, &p, @intCast(4 + share.len));
    putInt(u16, &p, @intFromEnum(group));
    putInt(u16, &p, @intCast(share.len));
    putBytes(&p, share);
    std.mem.writeInt(u24, in_buf[6..9], @intCast(p - 9), .big);
    std.mem.writeInt(u16, in_buf[3..5], @intCast(p - 5), .big);
    in_len = p;
}

// ── needles ─────────────────────────────────────────────────────────────────

/// HMAC's `key ⊕ ipad` and `key ⊕ opad` blocks.
fn addPads(n: *Needles, name: []const u8, key: []const u8) void {
    var a: [48]u8 = undefined;
    var b: [48]u8 = undefined;
    for (key, 0..) |k, i| {
        a[i] = k ^ 0x36;
        b[i] = k ^ 0x5c;
    }
    n.addImage(name, a[0..key.len]);
    n.addImage(name, b[0..key.len]);
}

fn Schedule(comptime Hash: type) type {
    return struct { s_ts: [Hash.digest_length]u8, master: [Hash.digest_length]u8 };
}

/// The handshake key schedule (RFC 8446 §7.1) for `shared`; returns the
/// server handshake traffic secret (the reach check looks for it in the key
/// log) and the master secret (a full flight derives the application secrets).
fn scheduleNeedles(comptime Hash: type, comptime aead_key_len: usize, n: *Needles, shared: []const u8, hello_hash: *const [Hash.digest_length]u8) Schedule(Hash) {
    const K = Hkdf(if (Hash == Sha256) Hmac.HmacSha256 else Hmac.HmacSha384);
    const dl = Hash.digest_length;
    const zeroes = [1]u8{0} ** dl;
    const early = K.extract(&[1]u8{0}, &zeroes);
    const empty = tls.emptyHash(Hash);
    const hs_derived = tls.hkdfExpandLabel(K, early, "derived", &empty, dl);
    const hs = K.extract(&hs_derived, shared);
    const ap_derived = tls.hkdfExpandLabel(K, hs, "derived", &empty, dl);
    const master = K.extract(&ap_derived, &zeroes);
    const c_ts = tls.hkdfExpandLabel(K, hs, "c hs traffic", hello_hash, dl);
    const s_ts = tls.hkdfExpandLabel(K, hs, "s hs traffic", hello_hash, dl);
    n.addBoth("shared", shared[0..@min(shared.len, 64)]);
    n.addBoth("hs secret", &hs);
    n.addBoth("ap derived", &ap_derived);
    n.addBoth("master", &master);
    n.addBoth("c hs ts", &c_ts);
    n.addBoth("s hs ts", &s_ts);
    n.addBoth("c fin key", &tls.hkdfExpandLabel(K, c_ts, "finished", "", dl));
    n.addBoth("s fin key", &tls.hkdfExpandLabel(K, s_ts, "finished", "", dl));
    n.addBoth("c hs key", &tls.hkdfExpandLabel(K, c_ts, "key", "", aead_key_len));
    n.addBoth("s hs key", &tls.hkdfExpandLabel(K, s_ts, "key", "", aead_key_len));
    addPads(n, "hmac pad", &hs);
    addPads(n, "hmac pad", &ap_derived);
    addPads(n, "hmac pad", &c_ts);
    addPads(n, "hmac pad", &s_ts);
    return .{ .s_ts = s_ts, .master = master };
}

// ── the server's encrypted flight (a full TLS 1.3 handshake) ────────────────
//
// ChangeCipherSpec, then EncryptedExtensions, Certificate, CertificateVerify
// and Finished, each in a record of its own under the server handshake key, appended to the
// ServerHello so `Client.init` returns an established session. The server
// certificate is the throwaway `client-p256` leaf (its key is in testdata);
// `.ca = .no_verification` skips the chain, but the CertificateVerify
// signature and the Finished MAC are checked as in any handshake.

const server_cert_der = derFromPem(@embedFile("testdata/client-p256.pem"));
const server_key_der = @embedFile("testdata/client-p256.key.der");

fn derFromPem(comptime pem: []const u8) []const u8 {
    const S = struct {
        const der = blk: {
            @setEvalBranchQuota(1_000_000);
            const begin = std.mem.indexOf(u8, pem, "-----\n").? + 6;
            const end = std.mem.indexOf(u8, pem, "\n-----END").?;
            var clean: [end - begin]u8 = undefined;
            var len: usize = 0;
            for (pem[begin..end]) |ch| if (ch != '\n') {
                clean[len] = ch;
                len += 1;
            };
            const b64 = clean[0..len];
            var out: [std.base64.standard.Decoder.calcSizeForSlice(b64) catch unreachable]u8 = undefined;
            std.base64.standard.Decoder.decode(&out, b64) catch unreachable;
            break :blk out;
        };
    };
    return &S.der;
}

/// One handshake message (`typ`, u24 length, `body`) into `buf`.
fn hsMsg(buf: []u8, typ: tls.HandshakeType, body: []const u8) []const u8 {
    buf[0] = @intFromEnum(typ);
    std.mem.writeInt(u24, buf[1..4], @intCast(body.len), .big);
    @memcpy(buf[4..][0..body.len], body);
    return buf[0 .. 4 + body.len];
}

/// `msg` as one TLS 1.3 record (inner type handshake) appended to `in_buf`.
fn appendRecord(comptime Aead: type, key: [Aead.key_length]u8, iv: [Aead.nonce_length]u8, seq: u64, msg: []const u8) void {
    var pt: [2048]u8 = undefined;
    @memcpy(pt[0..msg.len], msg);
    pt[msg.len] = @intFromEnum(tls.ContentType.handshake);
    const inner = pt[0 .. msg.len + 1];
    const rec = in_buf[in_len..];
    rec[0..3].* = .{ @intFromEnum(tls.ContentType.application_data), 3, 3 };
    std.mem.writeInt(u16, rec[3..5], @intCast(inner.len + Aead.tag_length), .big);
    var nonce = iv;
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    for (nonce[nonce.len - 8 ..], seq_be) |*b, s| b.* ^= s;
    Aead.encrypt(rec[5..][0..inner.len], rec[5 + inner.len ..][0..Aead.tag_length], inner, rec[0..5], nonce, key);
    in_len += 5 + inner.len + Aead.tag_length;
}

/// Appends the server's encrypted flight after the ServerHello in `in_buf`
/// and returns the client application traffic secret (the reach check looks
/// for it in the key log); adds the application secrets and keys as needles.
fn appendServerFlight(comptime Hash: type, comptime Aead: type, n: *Needles, sched: Schedule(Hash), transcript: *Hash) ![Hash.digest_length]u8 {
    const HmacT = if (Hash == Sha256) Hmac.HmacSha256 else Hmac.HmacSha384;
    const K = Hkdf(HmacT);
    const dl = Hash.digest_length;
    const key = tls.hkdfExpandLabel(K, sched.s_ts, "key", "", Aead.key_length);
    const iv = tls.hkdfExpandLabel(K, sched.s_ts, "iv", "", Aead.nonce_length);
    var buf: [2048]u8 = undefined;
    var body: [2048]u8 = undefined;

    // The middlebox-compatibility ChangeCipherSpec: std's client switches to
    // the handshake keys on it, not on the ServerHello.
    putBytes(&in_len, &.{ @intFromEnum(tls.ContentType.change_cipher_spec), 3, 3, 0, 1, 1 });

    const ee = hsMsg(&buf, .encrypted_extensions, &.{ 0, 0 });
    transcript.update(ee);
    appendRecord(Aead, key, iv, 0, ee);

    const der = server_cert_der;
    body[0] = 0; // certificate_request_context
    std.mem.writeInt(u24, body[1..4], @intCast(3 + der.len + 2), .big);
    std.mem.writeInt(u24, body[4..7], @intCast(der.len), .big);
    @memcpy(body[7..][0..der.len], der);
    std.mem.writeInt(u16, body[7 + der.len ..][0..2], 0, .big); // no extensions
    const cert = hsMsg(&buf, .certificate, body[0 .. 7 + der.len + 2]);
    transcript.update(cert);
    appendRecord(Aead, key, iv, 1, cert);

    // SEC1 ECPrivateKey: 30 77 02 01 01 04 20 <32-byte scalar> …
    try std.testing.expectEqualSlices(u8, "\x30\x77\x02\x01\x01\x04\x20", server_key_der[0..7]);
    const kp = try Es256.KeyPair.fromSecretKey(try Es256.SecretKey.fromBytes(server_key_der[7..39].*));
    const signed = " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00";
    var cv_msg: [signed.len + dl]u8 = undefined;
    cv_msg[0..signed.len].* = signed.*;
    cv_msg[signed.len..].* = transcript.peek();
    var sig_der: [Es256.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(&cv_msg, null)).toDer(&sig_der);
    std.mem.writeInt(u16, body[0..2], @intFromEnum(tls.SignatureScheme.ecdsa_secp256r1_sha256), .big);
    std.mem.writeInt(u16, body[2..4], @intCast(sig.len), .big);
    @memcpy(body[4..][0..sig.len], sig);
    const cv = hsMsg(&buf, .certificate_verify, body[0 .. 4 + sig.len]);
    transcript.update(cv);
    appendRecord(Aead, key, iv, 2, cv);

    const fin_key = tls.hkdfExpandLabel(K, sched.s_ts, "finished", "", HmacT.key_length);
    const verify_data = tls.hmac(HmacT, &transcript.peek(), fin_key);
    const fin = hsMsg(&buf, .finished, &verify_data);
    transcript.update(fin);
    appendRecord(Aead, key, iv, 3, fin);

    const h = transcript.peek();
    const c_ap = tls.hkdfExpandLabel(K, sched.master, "c ap traffic", &h, dl);
    const s_ap = tls.hkdfExpandLabel(K, sched.master, "s ap traffic", &h, dl);
    n.addBoth("c ap ts", &c_ap);
    n.addBoth("s ap ts", &s_ap);
    n.addBoth("c ap key", &tls.hkdfExpandLabel(K, c_ap, "key", "", Aead.key_length));
    n.addBoth("s ap key", &tls.hkdfExpandLabel(K, s_ap, "key", "", Aead.key_length));
    addPads(n, "hmac pad", &sched.master);
    addPads(n, "hmac pad", &c_ap);
    addPads(n, "hmac pad", &s_ap);
    return c_ap;
}

/// Every ephemeral secret the client holds, whatever group the server picks.
fn keyNeedles(n: *Needles) void {
    const mlkem_seed = kex_entropy[64..128];
    n.addBoth("mlkem seed", mlkem_seed);
    var g: [64]u8 = undefined;
    var h = Sha3_512.init(.{});
    h.update(mlkem_seed[0..32]);
    h.update(&[1]u8{3}); // ML-KEM-768: k = 3
    h.final(&g);
    n.addBoth("mlkem sigma", g[32..64]);
    const sk_bytes = keys.mlkem.secret_key.toBytes();
    n.addImage("mlkem sk", sk_bytes[0..1152]); // the encoded secret vector s
    n.addImage("mlkem sk", std.mem.asBytes(&keys.mlkem.secret_key.sk));

    n.addBoth("p256 seed", kex_entropy[128..160]);
    n.addScalar("p256 d", std.crypto.ecc.P256.scalar.Scalar.fromBytes(keys.p256.secret_key.bytes, .big) catch unreachable);
    n.addBoth("p384 seed", kex_entropy[160..208]);
    n.addScalar("p384 d", std.crypto.ecc.P384.scalar.Scalar.fromBytes(keys.p384.secret_key.bytes, .big) catch unreachable);

    n.addBoth("x25519 sk", &keys.x25519.secret_key);
    var clamped = keys.x25519.secret_key;
    Ed.scalar.clamp(&clamped);
    n.addBoth("x25519 sk", &clamped);
}

fn hex(comptime N: usize, b: *const [N]u8) [N * 2]u8 {
    return std.fmt.bytesToHex(b.*, .lower);
}

/// `full`: the server's whole first flight follows, and `Client.init` returns
/// an established session (application secrets); otherwise the input ends
/// after the ServerHello and the call fails on the truncation.
fn kexCase(comptime group: tls.NamedGroup, comptime suite: tls.CipherSuite, comptime full: bool, ci: u8) !usize {
    const Hash = switch (suite) {
        .AES_128_GCM_SHA256 => Sha256,
        .AES_256_GCM_SHA384 => Sha384,
        else => @compileError("suite"),
    };
    const key_len = if (Hash == Sha256) 16 else 32;
    const Aead = if (Hash == Sha256) std.crypto.aead.aes_gcm.Aes128Gcm else std.crypto.aead.aes_gcm.Aes256Gcm;

    kex_entropy = derive("tls-kex-entropy", ci, Client.Options.entropy_len);
    keys = .{
        .mlkem = try MLKem768.KeyPair.generateDeterministic(kex_entropy[64..128].*),
        .p256 = try Es256Pair.generateDeterministic(kex_entropy[128..160].*),
        .p384 = try Es384Pair.generateDeterministic(kex_entropy[160..208].*),
        .x25519 = try X25519.KeyPair.generateDeterministic(kex_entropy[208..240].*),
    };

    var n: Needles = .{};
    keyNeedles(&n);

    // The server's side, from fixed server secrets.
    var shared_buf: [64]u8 = undefined;
    var shared: []const u8 = undefined;
    var share_buf: [1200]u8 = undefined;
    var share: []const u8 = undefined;
    switch (group) {
        .x25519_ml_kem768, .x25519 => {
            const srv_sk = derive("tls-server-x25519", ci, 32);
            const srv_pub = try X25519.recoverPublicKey(srv_sk);
            const xs = try X25519.scalarmult(srv_sk, keys.x25519.public_key);
            n.addBoth("x25519 shared", &xs);
            if (group == .x25519) {
                share = &srv_pub;
                shared = &xs;
            } else {
                const m = derive("tls-server-mlkem-m", ci, 32);
                const enc = keys.mlkem.public_key.encapsDeterministic(&m);
                var kr: [64]u8 = undefined;
                var gh = Sha3_512.init(.{});
                gh.update(&m);
                gh.update(&keys.mlkem.public_key.hpk);
                gh.final(&kr);
                n.addBoth("mlkem m/K/r", &m);
                n.addBoth("mlkem m/K/r", &kr);
                n.addBoth("mlkem ss", &enc.shared_secret);
                @memcpy(share_buf[0..enc.ciphertext.len], &enc.ciphertext);
                @memcpy(share_buf[enc.ciphertext.len..][0..32], &srv_pub);
                share = share_buf[0 .. enc.ciphertext.len + 32];
                @memcpy(shared_buf[0..32], &enc.shared_secret);
                @memcpy(shared_buf[32..64], &xs);
                shared = &shared_buf;
            }
        },
        .secp256r1 => {
            const srv = try Es256Pair.generateDeterministic(derive("tls-server-p256", ci, 32));
            const sec1 = srv.public_key.toUncompressedSec1();
            @memcpy(share_buf[0..sec1.len], &sec1);
            share = share_buf[0..sec1.len];
            const x = (try keys.p256.public_key.p.mul(srv.secret_key.bytes, .big)).affineCoordinates().x;
            shared_buf[0..32].* = x.toBytes(.big);
            shared = shared_buf[0..32];
            n.addBoth("ecdh x", shared);
            n.addImage("ecdh x", std.mem.asBytes(&x));
        },
        .secp384r1 => {
            const srv = try Es384Pair.generateDeterministic(derive("tls-server-p384", ci, 48));
            const sec1 = srv.public_key.toUncompressedSec1();
            @memcpy(share_buf[0..sec1.len], &sec1);
            share = share_buf[0..sec1.len];
            const x = (try keys.p384.public_key.p.mul(srv.secret_key.bytes, .big)).affineCoordinates().x;
            shared_buf[0..48].* = x.toBytes(.big);
            shared = shared_buf[0..48];
            n.addBoth("ecdh x", shared);
            n.addImage("ecdh x", std.mem.asBytes(&x));
        },
        else => @compileError("group"),
    }
    buildFlight(ci, group, suite, share);

    // Reach: one logged run captures the ClientHello (the transcript) and must
    // show the handshake secret we recomputed.
    log_writer = Writer.fixed(&log_buf);
    key_log = .{ .client_key_seq = 0, .server_key_seq = 0, .client_random = undefined, .writer = &log_writer };
    use_key_log = true;
    callInit();
    use_key_log = false;
    try std.testing.expectEqual(@as(?anyerror, error.TlsConnectionTruncated), init_err);
    var th = Hash.init(.{});
    th.update(out_writer.buffered()[tls.record_header_len..]); // ClientHello
    th.update(in_buf[tls.record_header_len..in_len]); // ServerHello
    const hello_hash = th.peek();
    const sched = scheduleNeedles(Hash, key_len, &n, shared, &hello_hash);
    try std.testing.expect(std.mem.indexOf(u8, log_writer.buffered(), &hex(Hash.digest_length, &sched.s_ts)) != null);

    if (full) {
        // Reach: the whole flight is accepted and the client logs the
        // application secret we derived.
        const c_ap = try appendServerFlight(Hash, Aead, &n, sched, &th);
        log_writer = Writer.fixed(&log_buf);
        key_log = .{ .client_key_seq = 0, .server_key_seq = 0, .client_random = undefined, .writer = &log_writer };
        use_key_log = true;
        callInit();
        use_key_log = false;
        try std.testing.expectEqual(@as(?anyerror, null), init_err);
        try std.testing.expect(std.mem.indexOf(u8, log_writer.buffered(), &hex(Hash.digest_length, &c_ap)) != null);
    }

    n.sort();
    leak_src = keys.x25519.secret_key;
    const what = if (full) " full flight" else " ServerHello";
    return runProbe("Client.init " ++ @tagName(group) ++ " / " ++ @tagName(suite) ++ what, callInit, &n);
}

test "STACKPROBE: no ECDHE or handshake key-schedule residue on the dead stack after Client.init" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    var ci: u8 = 0;
    inline for (.{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1 }) |g| {
        inline for (.{ .AES_128_GCM_SHA256, .AES_256_GCM_SHA384 }) |s| {
            bad += try kexCase(g, s, false, ci);
            ci += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "STACKPROBE: no application secret residue on the dead stack after a full Client.init handshake" {
    try skipUnlessOptimized();
    var bad: usize = 0;
    var ci: u8 = 32;
    inline for (.{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1 }) |g| {
        inline for (.{ .AES_128_GCM_SHA256, .AES_256_GCM_SHA384 }) |s| {
            bad += try kexCase(g, s, true, ci);
            ci += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
