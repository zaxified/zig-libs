// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh saml`, which builds the
//! harness and prints the control table.
//!
//! Not wired into `zig build test-saml`: memcheck's context count is valgrind's
//! own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The one secret `saml` itself holds: the SP's RSA private key, used to sign its
//! own outgoing messages. Its secret members (d, p, q, dp, dq, qinv and the value
//! fields of p_mont/q_mont; NOT n, e, n_mont or the slot L) are tainted in place
//! after the fixtures are built, the public half stays defined:
//!
//!  * `sign` — `buildLogoutRequest` with `sign_with` (RSA-SHA256 over the
//!    exclusive-C14N `SignedInfo`) and `buildSignedRedirectQuery` (RSA-SHA256 over
//!    the query string).
//!
//! The finished signatures are public from the moment they are returned. They are
//! formatted through the non-constant-time printer BEFORE they are declassified,
//! as the propagation witness (a non-zero `total`). `saml` cannot declassify its
//! own intermediate: it base64-encodes the signature, which is public by
//! definition but still marked undefined here, and that is where all but one of
//! the in-file contexts come from (itemised in `ctgrind-expected.tsv`).
//!
//! ## What this does NOT measure, and why
//!
//! The decryption path (`EncryptedAssertion` / `EncryptedID` /
//! `EncryptedAttribute`). It was driven (`consumeLogoutRequestXml` over an
//! `EncryptedID`, key tainted): 95 in-file contexts, of which five are the
//! `rsa`/`aesgcm` verdicts that `xmlenc`'s own harness itemises, and the rest are
//! `xml.parse` and the extraction branching on the RECOVERED PLAINTEXT, which is
//! tainted because it derives from the key but is the output of the operation by
//! definition (the recipient's own data), and which `saml` has no way to
//! declassify. That row would measure the XML parser, not a key dependence, and
//! any bound loose enough to survive parser changes would hide a real one. The
//! key-dependent work on that path is `xmlenc.decryptData`, claimed in `xmlenc`'s
//! rows; `saml` adds none (no key material is handled in `saml`'s own code).

const std = @import("std");
const builtin = @import("builtin");
const saml = @import("root.zig");
const rsa = @import("rsa");

const memcheck = std.valgrind.memcheck;

const Target = enum { sign };
const Taint = enum { yes, no };

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

const kat_e = [_]u8{ 0x01, 0x00, 0x01 };
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) memcheck.makeMemUndefined(bytes);
}

fn taintMont(t: Taint, mp: anytype) void {
    taint(t, std.mem.asBytes(&mp.m));
    taint(t, std.mem.asBytes(&mp.n0inv));
    taint(t, std.mem.asBytes(&mp.r2));
    taint(t, std.mem.asBytes(&mp.one_mont));
}

fn taintKey(t: Taint, sk: *rsa.SecretKey) void {
    taint(t, std.mem.asBytes(&sk.d));
    taint(t, std.mem.asBytes(&sk.p));
    taint(t, std.mem.asBytes(&sk.q));
    taint(t, std.mem.asBytes(&sk.dp));
    taint(t, std.mem.asBytes(&sk.dq));
    taint(t, std.mem.asBytes(&sk.qinv));
    taintMont(t, &sk.p_mont);
    taintMont(t, &sk.q_mont);
}

/// Format a (possibly tainted) copy through the non-constant-time printer, then
/// declassify the original: it is public from here on.
fn publish(label: []const u8, bytes: []const u8) void {
    var copy: [64]u8 = undefined;
    const n = @min(bytes.len, copy.len);
    @memcpy(copy[0..n], bytes[0..n]);
    std.debug.print("ctgrind_result {s}={x}\n", .{ label, copy[0..n] });
    memcheck.makeMemDefined(@constCast(bytes));
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const t = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var kp: rsa.KeyPair = undefined;
    try rsa.SecretKey.fromPrimes(&kp.secret_key, &kat_p, &kat_q, &kat_e);
    defer kp.secret_key.deinit();
    kp.public_key = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);
    const alloc = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from

    switch (target) {
        .sign => {
            taintKey(t, &kp.secret_key);
            const lr = try saml.buildLogoutRequest(alloc, .{
                .id = "_lr1",
                .issue_instant = "2024-06-01T12:00:00Z",
                .issuer = "https://sp.example.org/metadata",
                .name_id = "alice@example.org",
                .sign_with = .{ .rsa = &kp.secret_key },
            });
            defer alloc.free(lr);
            // The signature sits mid-document: witness the window that starts at
            // it, then declassify everything (it is public once produced).
            const sv = std.mem.find(u8, lr, "<ds:SignatureValue>") orelse return error.NoSignature;
            publish("logout_request", lr[sv + 19 ..][0..64]);
            memcheck.makeMemDefined(lr);
            const field = try saml.encodeRedirectField(alloc, lr);
            defer alloc.free(field);
            const q = try saml.buildSignedRedirectQuery(alloc, .{
                .kind = .request,
                .message_field = field,
                .relay_state = "rs",
                .key = .{ .rsa = &kp.secret_key },
            });
            defer alloc.free(q);
            publish("redirect_query", q[std.mem.find(u8, q, "&Signature=").? + 11 ..][0..64]);
            std.debug.print("ctgrind_result sign lens={d},{d}\n", .{ lr.len, q.len });
        },
    }
}
