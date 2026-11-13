// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh webhooksig`, which builds
//! the harness and prints the control table.
//!
//! Not wired into `zig build test-webhooksig`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! Every secret webhooksig holds: HMAC secrets (raw bytes, `whsec_` text) and
//! the Ed25519 `whsk_` seed. Each secret is tainted in place, the public
//! half stays defined, and the public API is driven. A signature / MAC is
//! public the moment it is produced: a tainted copy is formatted through the
//! non-constant-time printer as the propagation witness, then the original is
//! declassified so verify's input adds no noise.
//!
//!  * `verify` — the signature COMPARISON: `verify` (GitHub `sha256=` hex),
//!    `verifyFormat` (SHA-1 hex, SHA-512 base64), `Verifier.verifyBody` over a
//!    two-secret rotation set, `stripe`, `slack` and `standard` verify, each
//!    run twice (the genuine value, then one octet flipped). The signatures
//!    are produced with an untainted copy of the secret, so the encoders see
//!    nothing tainted. The verdict of `timing_safe.eql` is the one value the
//!    module computes from the secret, and it never reaches a branch of the
//!    module (the harness prints it).
//!  * `sign` — the same secret tainted through every signer (`sign`,
//!    `signFormat`, `stripe`, `slack`, `standard`). The HMAC is public by
//!    design, but `encodeMac`'s hex table and std's base64 index by each MAC
//!    octet before the caller can declassify it: those contexts are the count.
//!  * `keys` — `standard.decodeSecret` / `encodeSecret` on the tainted
//!    `whsec_` body (b64ct, no secret-indexed table).
//!  * `ed25519` — `decodeSigningKey` on both `whsk_` layouts (32-byte seed and
//!    64-byte seed || public key; the 64-byte form compares the embedded
//!    public half in constant time) and `signEd25519`.
//!
//! The HMAC, SHA-2 and Ed25519 arithmetic are std's and are claimed in their
//! own rows; the contexts they raise on the tainted secret are expected here
//! too and are itemised in `ctgrind-expected.tsv`.

const std = @import("std");
const builtin = @import("builtin");
const wh = @import("root.zig");

const memcheck = std.valgrind.memcheck;
const Ed25519 = std.crypto.sign.Ed25519;

const Target = enum { verify, sign, keys, ed25519 };
const Taint = enum { yes, no };

const body = "{\"event\":\"ctgrind\",\"n\":1}";

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) memcheck.makeMemUndefined(bytes);
}

/// Witness: format a (possibly tainted) copy through the non-constant-time
/// printer, then declassify the original.
fn publish(label: []const u8, bytes: []u8) void {
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    std.debug.print("ctgrind_result {s}={x}\n", .{ label, copy[0..bytes.len] });
    memcheck.makeMemDefined(bytes);
}

var verdict_bits: u32 = 0;

fn verdict(label: []const u8, ok: bool) void {
    verdict_bits = verdict_bits *% 2 +% @intFromBool(ok);
    std.debug.print("ctgrind_result {s} ok={}\n", .{ label, ok });
}

fn flip(sig: []u8, at: usize) void {
    sig[at] = if (sig[at] == 'A') 'B' else 'A';
}

fn fill(buf: []u8, mul: usize, add: usize) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% mul +% add);
}

fn okOf(r: wh.VerifyError!void) bool {
    return if (r) true else |_| false;
}

/// The signature COMPARISON with the HMAC secret tainted. Every signature is
/// produced first with an UNTAINTED copy of the secret (so the encoders never
/// see a tainted MAC), then each verify runs twice (the genuine value, then
/// one octet flipped) against a tainted copy.
fn verifyTarget(t: Taint) !void {
    var pub_secret: [32]u8 = undefined;
    var secret: [32]u8 = undefined;
    var secret2: [32]u8 = undefined;
    fill(&pub_secret, 7, 3);
    fill(&secret, 7, 3);
    fill(&secret2, 11, 5);
    taint(t, &secret);
    taint(t, &secret2);

    // GitHub-style sha256= hex.
    var buf: [wh.signatureBufLen(wh.default_prefix)]u8 = undefined;
    const sig = try wh.sign(&pub_secret, body, &buf);
    verdict("sha256 accept", wh.verify(&secret, body, sig));
    var bad: [buf.len]u8 = buf;
    bad[10] = if (bad[10] == '0') '1' else '0';
    verdict("sha256 reject", wh.verify(&secret, body, &bad));

    // SHA-1 hex and SHA-512 base64.
    const f1: wh.Format = .{ .prefix = "sha1=", .digest = .sha1 };
    var b1: [128]u8 = undefined;
    const s1 = try wh.signFormat(f1, &pub_secret, body, &b1);
    verdict("sha1 accept", wh.verifyFormat(f1, &secret, body, s1));
    const f5: wh.Format = .{ .prefix = "", .digest = .sha512, .encoding = .base64 };
    var b5: [128]u8 = undefined;
    const s5 = try wh.signFormat(f5, &pub_secret, body, &b5);
    verdict("sha512b64 accept", wh.verifyFormat(f5, &secret, body, s5));
    var b5bad: [128]u8 = undefined;
    @memcpy(b5bad[0..s5.len], s5);
    flip(b5bad[0..s5.len], 3);
    verdict("sha512b64 reject", wh.verifyFormat(f5, &secret, body, b5bad[0..s5.len]));

    // Verifier over a rotation set: the secrets are copied into the heap, taint the copies.
    var v = try wh.Verifier.init(std.heap.page_allocator, .{ .secret = &secret2, .extra_secrets = &.{&pub_secret} });
    defer v.deinit();
    for (v.secrets.items) |s| taint(t, s);
    verdict("verifier accept", v.verifyBody(body, sig));
    verdict("verifier reject", v.verifyBody(body, &bad));

    // Stripe, Slack and Standard Webhooks.
    var sb: [2 + 20 + 4 + 64]u8 = undefined;
    const ss = try wh.stripe.sign(&sb, &pub_secret, 1700000000, body);
    verdict("stripe accept", okOf(wh.stripe.verify(&.{&secret}, ss, body, 1700000000, 300)));
    var sbad: [sb.len]u8 = sb;
    sbad[ss.len - 3] = if (sbad[ss.len - 3] == '0') '1' else '0';
    verdict("stripe reject", okOf(wh.stripe.verify(&.{&secret}, sbad[0..ss.len], body, 1700000000, 300)));
    var lb: [wh.slack.signature_len]u8 = undefined;
    const ls = try wh.slack.sign(&lb, &pub_secret, 1700000000, body);
    verdict("slack accept", okOf(wh.slack.verify(&.{&secret}, "1700000000", ls, body, 1700000000, 300)));
    var lbad: [lb.len]u8 = lb;
    lbad[10] = if (lbad[10] == '0') '1' else '0';
    verdict("slack reject", okOf(wh.slack.verify(&.{&secret}, "1700000000", &lbad, body, 1700000000, 300)));
    var vb: [wh.standard.v1_len]u8 = undefined;
    const vs = try wh.standard.sign(&vb, &pub_secret, "msg_ctgrind", 1700000000, body);
    const keys: wh.standard.Keys = .{ .secrets = &.{&secret} };
    verdict("standard accept", okOf(wh.standard.verify(keys, "msg_ctgrind", "1700000000", vs, body, 1700000000, 300)));
    var vbad: [vb.len]u8 = vb;
    flip(vbad[0..], 8);
    verdict("standard reject", okOf(wh.standard.verify(keys, "msg_ctgrind", "1700000000", &vbad, body, 1700000000, 300)));
    // The accept / reject pattern as one pinned value (the output pin reads `ctgrind_result=<hex>`).
    std.debug.print("ctgrind_result={x:0>8}\n", .{verdict_bits});
}

/// Signing with a tainted secret. The MAC is public by design, but the
/// module's encoders (`hex[...]`, std base64) index a table by each MAC octet
/// before the caller can declassify it: those contexts are the count.
fn signTarget(t: Taint) !void {
    var secret: [32]u8 = undefined;
    fill(&secret, 7, 3);
    taint(t, &secret);

    var buf: [wh.signatureBufLen(wh.default_prefix)]u8 = undefined;
    publish("sha256", @constCast(try wh.sign(&secret, body, &buf)));
    const f1: wh.Format = .{ .prefix = "sha1=", .digest = .sha1 };
    var b1: [128]u8 = undefined;
    publish("sha1", @constCast(try wh.signFormat(f1, &secret, body, &b1)));
    const f5: wh.Format = .{ .prefix = "", .digest = .sha512, .encoding = .base64 };
    var b5: [128]u8 = undefined;
    publish("sha512b64", @constCast(try wh.signFormat(f5, &secret, body, &b5)));
    var sb: [2 + 20 + 4 + 64]u8 = undefined;
    publish("stripe", @constCast(try wh.stripe.sign(&sb, &secret, 1700000000, body)));
    var lb: [wh.slack.signature_len]u8 = undefined;
    publish("slack", @constCast(try wh.slack.sign(&lb, &secret, 1700000000, body)));
    var vb: [wh.standard.v1_len]u8 = undefined;
    publish("v1", @constCast(try wh.standard.sign(&vb, &secret, "msg_ctgrind", 1700000000, body)));
}

/// The `whsec_` key TEXT and the raw key it decodes to. Only the base64 body
/// is tainted; the prefix is public.
fn keysTarget(t: Taint) !void {
    var raw: [32]u8 = undefined;
    fill(&raw, 13, 1);
    var text: [wh.standard.secret_prefix.len + 44]u8 = undefined;
    _ = try wh.standard.encodeSecret(&text, &raw); // untainted key in, public layout out
    taint(t, text[wh.standard.secret_prefix.len..]);
    var key_buf: [wh.standard.max_secret_len]u8 = undefined;
    const key = try wh.standard.decodeSecret(&key_buf, &text);
    // decodeSecret tainted `key`; now the encode direction from a tainted raw key.
    var re: [text.len]u8 = undefined;
    const re_text = try wh.standard.encodeSecret(&re, key);
    publish("encodeSecret", @constCast(re_text));
}

fn ed25519Target(t: Taint) !void {
    const seed: [32]u8 = @splat(0x42);
    const kp0 = try Ed25519.KeyPair.generateDeterministic(seed);
    var b64_seed: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&b64_seed, &seed);
    var seed_text: [wh.standard.signing_key_prefix.len + 44]u8 = undefined;
    @memcpy(seed_text[0..wh.standard.signing_key_prefix.len], wh.standard.signing_key_prefix);
    @memcpy(seed_text[wh.standard.signing_key_prefix.len..], &b64_seed);
    var full: [64]u8 = undefined;
    @memcpy(full[0..32], &seed);
    @memcpy(full[32..], &kp0.public_key.toBytes());
    var b64_full: [88]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&b64_full, &full);
    var full_text: [wh.standard.signing_key_prefix.len + 88]u8 = undefined;
    @memcpy(full_text[0..wh.standard.signing_key_prefix.len], wh.standard.signing_key_prefix);
    @memcpy(full_text[wh.standard.signing_key_prefix.len..], &b64_full);

    // decodeSigningKey: both layouts, the whole TEXT tainted.
    taint(t, seed_text[wh.standard.signing_key_prefix.len..]);
    taint(t, full_text[wh.standard.signing_key_prefix.len..]);
    var kp: Ed25519.KeyPair = undefined;
    try wh.standard.decodeSigningKey(&kp, &seed_text);
    var pub_a = kp.public_key.toBytes();
    publish("whsk32 public", pub_a[0..]); // witness on the (tainted-derived) public half, then declassified
    var kp64: Ed25519.KeyPair = undefined;
    try wh.standard.decodeSigningKey(&kp64, &full_text);
    var pub_b = kp64.public_key.toBytes();
    publish("whsk64 public", pub_b[0..]);

    // signEd25519 with a tainted secret key: the first 32 bytes are the seed,
    // the rest is the public key.
    var sk = try Ed25519.KeyPair.generateDeterministic(seed);
    taint(t, sk.secret_key.bytes[0..32]);
    var out: [wh.standard.v1a_len]u8 = undefined;
    var scratch: [128]u8 = undefined;
    const sig = try wh.standard.signEd25519(&out, &scratch, &sk, "msg_ctgrind", 1700000000, body);
    publish("v1a", @constCast(sig));
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const t = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .verify => try verifyTarget(t),
        .sign => try signTarget(t),
        .keys => try keysTarget(t),
        .ed25519 => try ed25519Target(t),
    }
}
