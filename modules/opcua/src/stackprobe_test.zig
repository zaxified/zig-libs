// SPDX-License-Identifier: MIT

//! Dead-stack probe for the secret-touching entry points of the security layer
//! (`testkit.stackprobe`): residue below each burn, and the channel keys / RSA
//! private key / password as needles in any frame. ReleaseFast only
//! (`skipUnlessOptimized`, a runtime skip, so the body is type-checked in every
//! mode). Not probed: `SecureChannel.open`, the `Session`/`Subscription`
//! request methods and `Connection.tick` (they need a live peer; their burns
//! sit over the probed leaves and are not measured).

const std = @import("std");
const security = @import("security.zig");
const encoding = @import("encoding.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 256 * 1024 });
const gpa = std.heap.page_allocator; // global-alloc-ok: leaks the probed calls' result slices on purpose; file-scope fixtures outlive the test block

var prng: std.Random.DefaultCsprng = undefined;
var client: security.ClientCredentials = undefined;
var server: security.ClientCredentials = undefined;
var generated: security.ClientCredentials = undefined;
var keys: security.ChannelKeys = undefined;
var key32: [32]u8 = undefined;
var iv16: [16]u8 = undefined;
var seed_out: [80]u8 = undefined;
var cbc: [64]u8 = undefined;
var sym_body: [48]u8 = undefined;
var sealed: []u8 = &.{};
var password = "correct horse battery staple".*;
var nonce: [32]u8 = undefined;
var token_blob: []u8 = &.{};
var opn_buf: [1024]u8 = undefined;
var opn_len: usize = 0;
var opn_enc_offset: usize = 0;
var opn_wire: []u8 = &.{};

fn fill(out: []u8, label: []const u8) void {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &h, .{});
    for (out, 0..) |*b, i| b.* = h[i % 32] ^ @as(u8, @truncate(i / 32));
}

fn setup() !void {
    prng = std.Random.DefaultCsprng.init([_]u8{0x42} ** 32);
    const opts = security.ClientCredentials.GenerateSelfSignedOptions{
        .modulus_bits = 512,
        .common_name = "opcua-probe-client",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
    };
    try security.ClientCredentials.generateSelfSigned(gpa, prng.random(), opts, &client);
    var sopts = opts;
    sopts.modulus_bits = 768;
    sopts.common_name = "opcua-probe-server";
    try security.ClientCredentials.generateSelfSigned(gpa, prng.random(), sopts, &server);
    fill(&nonce, "opcua probe server nonce");
    var cn: [32]u8 = undefined;
    fill(&cn, "opcua probe client nonce");
    keys = security.deriveKeys(&cn, &nonce, .basic256sha256);
    fill(&key32, "opcua probe aes key");
    fill(&iv16, "opcua probe iv");
    fill(&cbc, "opcua probe plaintext");
    fill(&sym_body, "opcua probe body");
    std.mem.writeInt(u32, sym_body[0..4], 7, .little);
    token_blob = try security.encryptUserTokenSecret(gpa, &password, &nonce, server.public_key, prng.random());
    sealed = try security.symmetricSealChunk(gpa, "MSG", 'F', &sym_body, .sign_and_encrypt, &keys, .client_to_server);

    // A plausible OPN body: ChannelId + real asymmetric header + SequenceHeader + payload.
    var w: std.Io.Writer = .fixed(&opn_buf);
    var e = encoding.Encoder.init(&w);
    try w.writeInt(u32, 0, .little);
    try security.encodeAsymmetricAlgorithmSecurityHeader(&e, .{
        .security_policy_uri = security.SecurityPolicy.basic256sha256.uri(),
        .sender_certificate = client.certificate_der,
        .receiver_certificate_thumbprint = &security.certificateThumbprint(server.certificate_der),
    });
    opn_enc_offset = w.buffered().len;
    try w.writeInt(u32, 1, .little);
    try w.writeInt(u32, 1, .little);
    try w.writeAll("opn-request-payload-bytes");
    opn_len = w.buffered().len;
    opn_wire = try security.sealAsymmetricMessage(gpa, prng.random(), "OPN", opn_buf[0..opn_len], opn_enc_offset, &client, server.certificate_der);
}

fn keyNeedles() [3][]const u8 {
    return .{ std.mem.asBytes(&keys), &key32, &iv16 };
}

test "STACKPROBE: no channel key, RSA key or password residue after any entry point" {
    try sp.skipUnlessOptimized();
    try setup();
    const kn = keyNeedles();
    const kb = &[_][]const u8{ kn[0], kn[1], kn[2] };

    _ = try P.run("pSha256", security.pSha256, .{ &nonce, &key32, &seed_out }, &[_][]const u8{ &nonce, &key32, &seed_out }, .{});
    _ = try P.run("aes256CbcEncrypt", security.aes256CbcEncrypt, .{ &key32, &iv16, &cbc }, kb, .{});
    _ = try P.run("aes256CbcDecrypt", security.aes256CbcDecrypt, .{ &key32, &iv16, &cbc }, kb, .{});
    _ = try P.run("symmetricSealChunk", security.symmetricSealChunk, .{ gpa, "MSG", 'F', &sym_body, .sign_and_encrypt, &keys, .client_to_server }, kb, .{});
    _ = try P.run("symmetricSignAndEncrypt", security.symmetricSignAndEncrypt, .{ gpa, "MSG", &sym_body, .sign, &keys, .client_to_server }, kb, .{});
    _ = try P.run("symmetricDecryptAndVerify", security.symmetricDecryptAndVerify, .{ gpa, sealed[0..8], sealed[8..], .sign_and_encrypt, &keys, .client_to_server }, kb, .{});

    const rsa_sk = std.mem.asBytes(&server.private_key);
    _ = try P.run("encryptUserTokenSecret", security.encryptUserTokenSecret, .{ gpa, &password, &nonce, server.public_key, prng.random() }, &[_][]const u8{&password}, .{});
    _ = try P.run("decryptUserTokenSecret", security.decryptUserTokenSecret, .{ gpa, token_blob, &server.private_key, &nonce }, &[_][]const u8{ rsa_sk, &password }, .{});
    _ = try P.run("sealAsymmetricMessage", security.sealAsymmetricMessage, .{ gpa, prng.random(), "OPN", opn_buf[0..opn_len], opn_enc_offset, &client, server.certificate_der }, &[_][]const u8{std.mem.asBytes(&client.private_key)}, .{});
    _ = try P.run("openAsymmetricMessage", security.openAsymmetricMessage, .{ gpa, opn_wire[0..8], opn_wire[8..], &server.private_key, client.certificate_der }, &[_][]const u8{rsa_sk}, .{});

    const opts = security.ClientCredentials.GenerateSelfSignedOptions{
        .modulus_bits = 512,
        .common_name = "opcua-probe-generated",
        .not_before = "260101000000Z",
        .not_after = "270101000000Z",
    };
    _ = try P.run("ClientCredentials.generateSelfSigned", security.ClientCredentials.generateSelfSigned, .{ gpa, prng.random(), opts, &generated }, &[_][]const u8{std.mem.asBytes(&generated.private_key)}, .{});
}
