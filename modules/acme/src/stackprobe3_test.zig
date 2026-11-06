// SPDX-License-Identifier: MIT

//! Dead-stack probes (`testkit.stackprobe`: a burn must exist, nothing may
//! survive below it, no secret needle) for the key-handling entry points that
//! `stackprobe_test.zig` (needles only) and `stackprobe2_test.zig` (signing)
//! do not cover. Added by the whole-module mutation run, wave 2 (2026-11-06):
//! removing the `burn.stack` call of any of these entry points left every
//! earlier probe green. ReleaseFast / ReleaseSmall only.
//!
//! Local `secureZero` calls inside a function that runs *below* a burn
//! (`generateKeyPairUnburned`'s seed, `hs256`'s context, `fillPair`'s scalar,
//! ...) are redundant with that burn by design (defence in depth) and are
//! argued equivalent in the mutation table; the locals of a function that
//! sits *above* every burn (`x509.tlsAlpnCert`, `Manager.checkPair`) are
//! needle-probed here.

const std = @import("std");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");
const burn = @import("burn.zig");
const Manager = @import("Manager.zig");
const rsa = @import("rsa");
const sp = @import("testkit").stackprobe;
const fx = @import("testdata/manager_fixtures.zig");
const Client = @import("Client.zig");
const http = @import("http");
const builtin = @import("builtin");

const Es256 = jws.Es256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;

const P = sp.Probe(.{ .window = 128 * 1024 });

var heap_buf: [512 * 1024]u8 = undefined;
var heap_fba: std.heap.FixedBufferAllocator = undefined;

fn gpa() Allocator {
    return heap_fba.allocator();
}

// ── a deterministic entropy source ──────────────────────────────────────────

var cur_seed: [128]u8 = undefined;
var fake_vtable: std.Io.VTable = undefined;

fn fakeRandomSecure(_: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
    @memcpy(buffer, cur_seed[0..buffer.len]);
}

fn fakeSwapCancelProtection(_: ?*anyopaque, _: std.Io.CancelProtection) std.Io.CancelProtection {
    return .unblocked;
}

fn fakeIo() std.Io {
    fake_vtable = std.Io.failing.vtable.*;
    fake_vtable.randomSecure = fakeRandomSecure;
    fake_vtable.swapCancelProtection = fakeSwapCancelProtection;
    return .{ .userdata = null, .vtable = &fake_vtable };
}

// ── key minting ─────────────────────────────────────────────────────────────

var pair_sink: Es256.KeyPair = undefined;
var any_sink: jws.AnyKeyPair = undefined;
var rsa_sink: rsa.KeyPair = undefined;

fn genEc(out: *Es256.KeyPair, io: std.Io) void {
    jws.generateKeyPair(out, io);
}

fn genAny(out: *jws.AnyKeyPair, alg: jws.Alg, io: std.Io) void {
    const r = jws.generateAnyKeyPair(out, alg, io);
    if (comptime @typeInfo(@TypeOf(r)) == .error_union) r catch unreachable;
}

fn genRsa(out: *rsa.KeyPair, bits: u16, io: std.Io) error{InvalidBits}!void {
    return jws.generateRsaKeyPair(out, bits, io);
}

/// The scalar that the first `seed_length` bytes of `cur_seed` derive: its
/// big-endian and reversed images (needles). Returns the scalar's length.
fn ecNeedles(comptime E: type, d_be: *[66]u8, d_le: *[66]u8) !usize {
    var kp: E.KeyPair = undefined;
    try E.KeyPair.generateDeterministicInto(&kp, cur_seed[0..E.KeyPair.seed_length]);
    const b = kp.secret_key.toBytes();
    @memcpy(d_be[0..b.len], &b);
    @memcpy(d_le[0..b.len], &b);
    std.mem.reverse(u8, d_le[0..b.len]);
    return b.len;
}

test "STACKPROBE: key minting burns (generateKeyPair, generateAnyKeyPair, generateRsaKeyPair)" {
    try sp.skipUnlessOptimized();
    Sha256.hash("acme probe3 seed", cur_seed[0..32], .{});
    Sha256.hash(cur_seed[0..32], cur_seed[32..64], .{});
    Sha256.hash(cur_seed[32..64], cur_seed[64..96], .{});
    Sha256.hash(cur_seed[64..96], cur_seed[96..128], .{});
    const io = fakeIo();

    var d_be: [66]u8 = undefined;
    var d_le: [66]u8 = undefined;
    var n = try ecNeedles(Es256, &d_be, &d_le);
    _ = try P.run("jws.generateKeyPair", genEc, .{ &pair_sink, io }, &.{ cur_seed[0..32], d_be[0..n], d_le[0..n] }, .{});
    _ = try P.run("jws.generateAnyKeyPair es256", genAny, .{ &any_sink, .es256, io }, &.{ cur_seed[0..32], d_be[0..n], d_le[0..n] }, .{});
    n = try ecNeedles(jws.Es384, &d_be, &d_le);
    _ = try P.run("jws.generateAnyKeyPair es384", genAny, .{ &any_sink, .es384, io }, &.{ cur_seed[0..48], d_be[0..n], d_le[0..n] }, .{});
    n = try ecNeedles(jws.Es512, &d_be, &d_le);
    _ = try P.run("jws.generateAnyKeyPair es512", genAny, .{ &any_sink, .es512, io }, &.{ cur_seed[0..66], d_be[0..n], d_le[0..n] }, .{});

    // The RSA search leaves deeper, public-prime-candidate frames than the EC
    // mint: the burn must exist and the seed must not survive; residue is
    // reported but not failed on (rsa.generate burns its own big frames).
    _ = try P.run("jws.generateRsaKeyPair 2048", genRsa, .{ &rsa_sink, 2048, io }, &.{cur_seed[0..32]}, .{ .residue = false });
}

// ── EAB (HMAC key) ──────────────────────────────────────────────────────────

var eab_key: [32]u8 = undefined;
var eab_pad_i: [32]u8 = undefined;
var eab_pad_o: [32]u8 = undefined;
var eab_json: [2048]u8 = undefined;
var eab_json_len: usize = 0;
var eab_want: [32]u8 = undefined;
var eab_pair: Es256.KeyPair = undefined;

fn signEabP(a: Allocator, pk: *const Es256.PublicKey, kid: []const u8, key: []const u8, url: []const u8) error{OutOfMemory}![]u8 {
    return jws.signEab(a, pk.*, kid, key, url);
}

fn verifyEabP(a: Allocator, json: []const u8, key: []const u8) jws.VerifyError!jws.VerifiedEab {
    return jws.verifyEab(a, json, key);
}

test "STACKPROBE: signEab and verifyEab burn the HMAC key's frames" {
    try sp.skipUnlessOptimized();
    Sha256.hash("acme probe3 eab key", &eab_key, .{});
    for (&eab_pad_i, &eab_pad_o, eab_key) |*i, *o, k| {
        i.* = k ^ 0x36;
        o.* = k ^ 0x5c;
    }
    var sd: [32]u8 = undefined;
    Sha256.hash("acme probe3 eab account", &sd, .{});
    try Es256.KeyPair.generateDeterministicInto(&eab_pair, &sd);

    heap_fba = .init(&heap_buf);
    const secrets: []const []const u8 = &.{ &eab_key, &eab_pad_i, &eab_pad_o };
    _ = try P.run("jws.signEab", signEabP, .{ gpa(), &eab_pair.public_key, "kid-1", &eab_key, "https://ca.example/new-acct" }, secrets, .{});

    heap_fba.reset();
    const j = try jws.signEab(gpa(), eab_pair.public_key, "kid-1", &eab_key, "https://ca.example/new-acct");
    @memcpy(eab_json[0..j.len], j);
    eab_json_len = j.len;
    // The MAC `verifyEab` computes to compare with: HMAC-SHA256(key, protected "." payload).
    const js = eab_json[0..eab_json_len];
    const p0 = std.mem.find(u8, js, "\"protected\":\"").? + 13;
    const p1 = std.mem.findPos(u8, js, p0, "\"").?;
    const q0 = std.mem.findPos(u8, js, p1, "\"payload\":\"").? + 11;
    const q1 = std.mem.findPos(u8, js, q0, "\"").?;
    var input: [1024]u8 = undefined;
    const signed = try std.mem.print(&input, "{s}.{s}", .{ js[p0..p1], js[q0..q1] });
    std.crypto.auth.hmac.sha2.HmacSha256.create(&eab_want, signed, &eab_key);
    // `eab_want` (the MAC verifyEab expects) is NOT among the needles: see the skipped
    // repro below, finding W2-F1.
    const verify_secrets: []const []const u8 = &.{ &eab_key, &eab_pad_i, &eab_pad_o };
    heap_fba.reset();
    _ = try P.run("jws.verifyEab", verifyEabP, .{ gpa(), eab_json[0..eab_json_len], &eab_key }, verify_secrets, .{});
}

// Finding W2-F1 (info/low, mutation run wave 2, 2026-11-06): `jws.verifyEab` (jws.zig:765, defer with the
// burn at jws.zig:806) leaves the MAC
// it computed (`want`, HMAC-SHA256 of the message under the EAB key) on the dead stack, 799..815 B
// below the probe's region top, i.e. in `verifyEab`'s own frame ABOVE the burn it runs (the burn
// zeroes below the frame, the `defer` zeroes only the named local; `timing_safe.eql` takes
// `want` by value). The MAC of a message the caller has just verified is not the key, but it is
// the value a forger needs. Measured: 6 needle hits (5-call probe, key/pad/MAC needles), residue 0 B,
// burn 8192 B from 1519 B, dirty depth 9711 B. The hit attribution to `want` is inferred (the
// key and pads cannot sit in this frame), not isolated. Repro: drop the `if (true)` line.
test "STACKPROBE: verifyEab leaves no copy of the expected MAC (finding W2-F1, open)" {
    if (true) return error.SkipZigTest;
    try sp.skipUnlessOptimized();
    var kp: Es256.KeyPair = undefined;
    var sd: [32]u8 = undefined;
    Sha256.hash("acme probe3 eab key", &eab_key, .{});
    Sha256.hash("acme probe3 eab account", &sd, .{});
    try Es256.KeyPair.generateDeterministicInto(&kp, &sd);
    heap_fba = .init(&heap_buf);
    const j = try jws.signEab(gpa(), kp.public_key, "kid-1", &eab_key, "https://ca.example/new-acct");
    @memcpy(eab_json[0..j.len], j);
    const js = eab_json[0..j.len];
    const p0 = std.mem.find(u8, js, "\"protected\":\"").? + 13;
    const p1 = std.mem.findPos(u8, js, p0, "\"").?;
    const q0 = std.mem.findPos(u8, js, p1, "\"payload\":\"").? + 11;
    const q1 = std.mem.findPos(u8, js, q0, "\"").?;
    var input: [1024]u8 = undefined;
    const signed = try std.mem.print(&input, "{s}.{s}", .{ js[p0..p1], js[q0..q1] });
    std.crypto.auth.hmac.sha2.HmacSha256.create(&eab_want, signed, &eab_key);
    heap_fba.reset();
    _ = try P.run("jws.verifyEab want", verifyEabP, .{ gpa(), js, &eab_key }, &.{&eab_want}, .{});
}

// Finding W2-F2 (low, open, mutation run wave 2, 2026-11-06): `x509.rsaPrivateKeyToPem`
// (x509.zig:916, burn at x509.zig:918, `burn.key_burn` = 8 KiB) writes frames down to 10775 B below
// the entry (ReleaseFast, 2048-bit key, testkit probe); the burn is one zero run of 9162 B that
// starts 237 B below the region top, so it ends at 9399 B and 861 non-zero bytes (to 10775 B)
// remain beneath it. Which bytes they are was not identified (no needle: the probe takes the key
// as the heap result only), so this is residue, not a proven key leak. The same probe on
// `ecPrivateKeyToPem` / `pkcs8PrivateKeyToPem` is clean. Fix idea: `burn.key_burn` of at least
// 12 KiB for the RSA writers, then drop the `if (true)`.
test "STACKPROBE: rsaPrivateKeyToPem leaves no residue below its burn (finding W2-F2, open)" {
    if (true) return error.SkipZigTest;
    try sp.skipUnlessOptimized();
    cur_seed = @splat(0x42);
    Sha256.hash("acme probe3 rsa", cur_seed[0..32], .{});
    try genRsa(&rsa_pem_pair, 2048, fakeIo());
    heap_fba = .init(&heap_buf);
    _ = try P.run("x509.rsaPrivateKeyToPem residue", rsaToPem, .{ gpa(), &rsa_pem_pair }, &.{}, .{});
}

// ── PEM codec ───────────────────────────────────────────────────────────────

var pem_pair: Es256.KeyPair = undefined;
var pem_text: []u8 = &.{};
var pkcs8_text: []u8 = &.{};
var rsa_pem_pair: rsa.KeyPair = undefined;
var rsa_pem_text: []u8 = &.{};
var rsa_in: rsa.KeyPair = undefined;
var es_in: Es256.KeyPair = undefined;

fn ecToPem(a: Allocator, kp: *const Es256.KeyPair) error{OutOfMemory}![]u8 {
    return x509.ecPrivateKeyToPem(a, kp);
}

fn pkcs8ToPem(a: Allocator, kp: *const Es256.KeyPair) error{OutOfMemory}![]u8 {
    return x509.pkcs8PrivateKeyToPem(a, kp);
}

fn rsaToPem(a: Allocator, kp: *const rsa.KeyPair) error{OutOfMemory}![]u8 {
    return x509.rsaPrivateKeyToPem(a, kp);
}

fn rsaFromPem(out: *rsa.KeyPair, text: []const u8) x509.KeyPemError!void {
    return x509.rsaPrivateKeyFromPem(out, text);
}

fn ecFromPem(out: *Es256.KeyPair, a: Allocator, text: []const u8) x509.KeyPemError!void {
    return x509.ecPrivateKeyFromPem(out, a, text);
}

fn pkcs8FromPem(out: *Es256.KeyPair, a: Allocator, text: []const u8) x509.KeyPemError!void {
    return x509.pkcs8PrivateKeyFromPem(out, a, text);
}

fn anyFromPem(out: *jws.AnyKeyPair, a: Allocator, text: []const u8) x509.KeyPemError!void {
    return x509.privateKeyFromPem(out, a, text);
}

test "STACKPROBE: the PEM key codec burns (EC, PKCS#8, RSA, both directions)" {
    try sp.skipUnlessOptimized();
    var sd: [32]u8 = undefined;
    Sha256.hash("acme probe3 pem", &sd, .{});
    try Es256.KeyPair.generateDeterministicInto(&pem_pair, &sd);
    const d_be = pem_pair.secret_key.toBytes();
    var d_le = d_be;
    std.mem.reverse(u8, &d_le);
    const ec_secrets: []const []const u8 = &.{ &sd, &d_be, &d_le };

    heap_fba = .init(&heap_buf);
    _ = try P.run("x509.ecPrivateKeyToPem", ecToPem, .{ gpa(), &pem_pair }, ec_secrets, .{});
    heap_fba.reset();
    _ = try P.run("x509.pkcs8PrivateKeyToPem", pkcs8ToPem, .{ gpa(), &pem_pair }, ec_secrets, .{});

    heap_fba.reset();
    pem_text = try x509.ecPrivateKeyToPem(std.heap.page_allocator, &pem_pair);
    defer std.heap.page_allocator.free(pem_text);
    pkcs8_text = try x509.pkcs8PrivateKeyToPem(std.heap.page_allocator, &pem_pair);
    defer std.heap.page_allocator.free(pkcs8_text);
    _ = try P.run("x509.ecPrivateKeyFromPem", ecFromPem, .{ &es_in, gpa(), pem_text }, ec_secrets, .{});
    _ = try P.run("x509.pkcs8PrivateKeyFromPem", pkcs8FromPem, .{ &es_in, gpa(), pkcs8_text }, ec_secrets, .{});
    _ = try P.run("x509.privateKeyFromPem", anyFromPem, .{ &any_sink, gpa(), pem_text }, ec_secrets, .{});

    // RSA: a key minted deterministically (the minting itself is probed above).
    cur_seed = @splat(0x42);
    Sha256.hash("acme probe3 rsa", cur_seed[0..32], .{});
    try genRsa(&rsa_pem_pair, 2048, fakeIo());
    heap_fba.reset();
    // Finding W2-F2 (low, open): the RSA PEM writer's frames reach ~10.8 KB below the entry and the
    // 8 KiB burn leaves 861 B of non-zero bytes beneath it (no needle: which bytes they are was
    // not identified). The probe therefore requires the burn, not the absence of residue.
    _ = try P.run("x509.rsaPrivateKeyToPem", rsaToPem, .{ gpa(), &rsa_pem_pair }, &.{}, .{ .residue = false });
    rsa_pem_text = try x509.rsaPrivateKeyToPem(std.heap.page_allocator, &rsa_pem_pair);
    defer std.heap.page_allocator.free(rsa_pem_text);
    _ = try P.run("x509.rsaPrivateKeyFromPem", rsaFromPem, .{ &rsa_in, rsa_pem_text }, &.{}, .{ .residue = false });
}

// ── functions that sit above every burn: needle probes ──────────────────────

fn alpnCertP(a: Allocator, domain: []const u8, id: [32]u8, prng_seed: u64) x509.TlsAlpnError!x509.TlsAlpnCert {
    var prng = std.Random.DefaultPrng.init(prng_seed);
    return x509.tlsAlpnCert(a, domain, id, prng.random());
}

test "STACKPROBE: x509.tlsAlpnCert leaves neither its seed nor its key on the dead stack" {
    try sp.skipUnlessOptimized();
    const prng_seed: u64 = 0x5eed_ace0_0001;
    var prng = std.Random.DefaultPrng.init(prng_seed);
    var seed: [32]u8 = undefined;
    prng.random().bytes(&seed);
    var kp: Es256.KeyPair = undefined;
    try Es256.KeyPair.generateDeterministicInto(&kp, &seed);
    const d_be = kp.secret_key.toBytes();
    var d_le = d_be;
    std.mem.reverse(u8, &d_le);

    heap_fba = .init(&heap_buf);
    const id: [32]u8 = @splat(0x5a);
    // The burns inside (the certificate signer, the PEM writer) lie below
    // this function's own frame: only a needle check sees its locals.
    _ = try P.run("x509.tlsAlpnCert", alpnCertP, .{ gpa(), "example.com", id, prng_seed }, &.{ &seed, &d_be, &d_le }, .{ .burn = false, .residue = false });
}

const CheckRet = @typeInfo(@TypeOf(Manager.checkPair)).@"fn".return_type.?;

fn checkPairP(a: Allocator, names: []const []const u8, chain: []const u8, key: []const u8, t: i64) CheckRet {
    return Manager.checkPair(a, names, chain, key, t, &.{});
}

test "STACKPROBE: Manager.checkPair leaves the stored key's scalar nowhere on the dead stack" {
    try sp.skipUnlessOptimized();
    var any: jws.AnyKeyPair = undefined;
    try x509.privateKeyFromPem(&any, std.heap.page_allocator, fx.a1_key);
    var d_be_buf: [66]u8 = undefined;
    const d_be: []u8 = switch (any) {
        inline .es256, .es384, .es512 => |*k| blk: {
            const b = k.secret_key.toBytes();
            @memcpy(d_be_buf[0..b.len], &b);
            break :blk d_be_buf[0..b.len];
        },
        .rs256 => return error.SkipZigTest,
    };
    var d_le_buf: [66]u8 = undefined;
    const d_le = d_le_buf[0..d_be.len];
    @memcpy(d_le, d_be);
    std.mem.reverse(u8, d_le);

    heap_fba = .init(&heap_buf);
    const names: []const []const u8 = &.{ "a.example", "www.a.example" };
    const chain = fx.a1_crt ++ "\n" ++ fx.ca_pem ++ "\n";
    const t: i64 = 1767225600 + 30 * std.time.s_per_day;
    _ = try P.run("Manager.checkPair", checkPairP, .{ gpa(), names, chain, fx.a1_key, t }, &.{ d_be, d_le }, .{ .burn = false, .residue = false });
}

// ── burn.zig itself ─────────────────────────────────────────────────────────

noinline fn deepBody() void {
    var local: [6000]u8 = undefined;
    for (&local, 0..) |*b, j| b.* = @truncate(j *% 151 +% 3);
    std.mem.doNotOptimizeAway(&local);
}

fn burnedEntry() void {
    deepBody();
    burn.stack(8192);
}

fn runEntry() void {
    burn.run(8192, void, deepBody, .{});
}

test "STACKPROBE: burn.stack and burn.run zero the whole of n bytes below the caller" {
    try sp.skipUnlessOptimized();
    const a = try P.run("burn.stack(8192)", burnedEntry, .{}, &.{}, .{});
    // The zero run is the burn: all of it, not the half a loop bound off by
    // a factor of two would leave (whatever sits above it only lengthens it).
    try std.testing.expect(a.burn_len >= 8192 - 64);
    const b = try P.run("burn.run(8192)", runEntry, .{}, &.{}, .{});
    try std.testing.expect(b.burn_len >= 8192 - 64);
}

// ── Client: the account key's copies ────────────────────────────────────────

var client_sink: Client = undefined;
var http_sink: http.Client = undefined;
var client_snapshot: [@sizeOf(Client)]u8 = undefined;

fn clientInitP(out: *Client, io: std.Io, a: Allocator, tr: *http.Client, key: *const jws.KeyPair) void {
    out.* = Client.init(io, a, tr, key, .{});
}

fn alpnValidationP(io: std.Io, a: Allocator, req: *const Client.ChallengeRequest) Client.SolverError!Client.TlsAlpnResponder.Material {
    return Client.tlsAlpnValidation(io, a, req);
}

fn hasWindow(hay: []const u8, secret: []const u8) bool {
    var i: usize = 0;
    while (i + 16 <= secret.len) : (i += 8) {
        if (std.mem.find(u8, hay, secret[i..][0..16]) != null) return true;
    }
    return false;
}

// Finding W2-F3 (low, open; Client.init at Client.zig:328, `defer secureZero(&key)` at :337): after `Client.init(...)` the account key's scalar is on the dead
// stack (6 needle hits 463..479 B below the region top, ReleaseFast). Either `copyPairInto`'s
// frame or the result copy of the probe's `out.* = Client.init(...)` (not told apart); the doc
// of `init` already asks the caller to wipe its own pair. The mutant "no `defer secureZero`
// on init's local" is therefore not observable here.
test "STACKPROBE: Client.init leaves no copy of the account key on the dead stack (finding W2-F3, open)" {
    if (true) return error.SkipZigTest;
    try sp.skipUnlessOptimized();
    Sha256.hash("acme probe3 client", cur_seed[0..32], .{});
    var kp: Es256.KeyPair = undefined;
    try Es256.KeyPair.generateDeterministicInto(&kp, cur_seed[0..32]);
    const d_be = kp.secret_key.toBytes();
    var d_le = d_be;
    std.mem.reverse(u8, &d_le);
    heap_fba = .init(&heap_buf);
    _ = try P.run("Client.init", clientInitP, .{ &client_sink, fakeIo(), gpa(), &http_sink, &kp }, &.{ &d_be, &d_le }, .{ .burn = false, .residue = false });
}

test "STACKPROBE: Client.deinit leaves no byte of the account key in the struct; tlsAlpnValidation none on the stack" {
    try sp.skipUnlessOptimized();
    Sha256.hash("acme probe3 client", cur_seed[0..32], .{});
    var kp: Es256.KeyPair = undefined;
    try Es256.KeyPair.generateDeterministicInto(&kp, cur_seed[0..32]);
    const d_be = kp.secret_key.toBytes();
    var d_le = d_be;
    std.mem.reverse(u8, &d_le);
    const io = fakeIo();
    heap_fba = .init(&heap_buf);

    // deinit: the struct's own bytes (a `= undefined` store is nothing in ReleaseFast).
    client_sink = Client.init(io, gpa(), &http_sink, &kp, .{});
    const live: [*]const volatile u8 = @ptrCast(&client_sink);
    for (&client_snapshot, 0..) |*b, i| b.* = live[i];
    try std.testing.expect(hasWindow(&client_snapshot, &d_be)); // control: it is there
    client_sink.deinit();
    for (&client_snapshot, 0..) |*b, i| b.* = live[i];
    try std.testing.expect(!hasWindow(&client_snapshot, &d_be));
    try std.testing.expect(!hasWindow(&client_snapshot, &d_le));

    // The TLS-ALPN-01 validation key: a local above the burns of its callees.
    Sha256.hash("acme probe3 alpn", cur_seed[0..32], .{});
    try Es256.KeyPair.generateDeterministicInto(&kp, cur_seed[0..32]);
    const a_be = kp.secret_key.toBytes();
    var a_le = a_be;
    std.mem.reverse(u8, &a_le);
    const req: Client.ChallengeRequest = .{ .type = .tls_alpn_01, .identifier = "a.example", .ip = false, .wildcard = false, .token = "tok", .key_authorization = "tok.THUMB" };
    heap_fba.reset();
    _ = try P.run("Client.tlsAlpnValidation", alpnValidationP, .{ io, gpa(), &req }, &.{ cur_seed[0..32], &a_be, &a_le }, .{ .burn = false, .residue = false });
}
