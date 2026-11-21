// SPDX-License-Identifier: MIT

//! Foreign check of `xmlenc.encryptData`: the `<xenc:EncryptedData>` it writes must be decrypted by xmlsec1 (C,
//! OpenSSL backend, run as a black box) to the exact plaintext, for every content algorithm (AES-128/192/256 in CBC
//! and GCM) under every key delivery (RSA-OAEP with the SHA-1 legacy URI and the xenc11 digest / MGF pairs, and
//! AES key wrap with 128/192/256-bit KEKs), as an element (`Type=#Element`) and as content (`Type=#Content`); and the
//! ECDH-ES key agreement (P-256, P-384, P-521; ConcatKDF with SHA-1/256/384/512 and parties of different shapes) with
//! the recipient's private key and, by name, the originator's public key. (xmlsec1 neither writes nor reads a
//! `dsig11:ECKeyValue`: the program swaps the originator key in our document for a key name and hands xmlsec1 the
//! ephemeral public key as PEM. The other direction, xmlsec1 writing and `decryptData` reading, is the fixture of
//! `src/ecdh_fixtures.zig`, made by `tools/gen_ecdh_fixtures.py`.)
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-xmlenc` runs it and `zig build check-interop` compiles it. Needs
//! `xmlsec1` (>= 1.3, OpenSSL backend) and `openssl` on PATH; if either is missing the program says so and exits 2.
//! No network. Run from the repository root; scratch files go to `.zig-cache/interop-xmlenc/`. Exit 0 = every
//! combination decrypted to the exact plaintext.

const std = @import("std");
const xmlenc = @import("xmlenc");
const rsa = @import("rsa");

const work_dir = ".zig-cache/interop-xmlenc";

fn run(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8) !std.process.RunResult {
    return std.process.run(arena, io, .{ .argv = argv });
}

fn ok(r: std.process.RunResult) bool {
    return r.term == .exited and r.term.exited == 0;
}

const Curve = struct {
    openssl_name: []const u8,
    curve: xmlenc.EcCurve,
    width: usize,
    /// DER `SubjectPublicKeyInfo` bytes in front of the uncompressed point.
    spki_prefix_hex: []const u8,
};

const curves = [_]Curve{
    .{ .openssl_name = "prime256v1", .curve = .p256, .width = 32, .spki_prefix_hex = "3059301306072a8648ce3d020106082a8648ce3d030107034200" },
    .{ .openssl_name = "secp384r1", .curve = .p384, .width = 48, .spki_prefix_hex = "3076301006072a8648ce3d020106052b81040022036200" },
    .{ .openssl_name = "secp521r1", .curve = .p521, .width = 66, .spki_prefix_hex = "30819b301006072a8648ce3d020106052b8104002303818600" },
};

/// The hex digits between `from` and `to` in `text` (openssl's colon-separated dump), as bytes.
fn dumpBetween(arena: std.mem.Allocator, text: []const u8, from: []const u8, to: []const u8) ![]u8 {
    const a = (std.mem.find(u8, text, from) orelse return error.BadDump) + from.len;
    const b = std.mem.findPos(u8, text, a, to) orelse return error.BadDump;
    var digits: std.ArrayList(u8) = .empty;
    for (text[a..b]) |c| if (std.ascii.isHex(c)) try digits.append(arena, c);
    const out = try arena.alloc(u8, digits.items.len / 2);
    _ = try std.fmt.hexToBytes(out, digits.items);
    return out;
}

/// The ECDH-ES documents of `encryptData` read by xmlsec1; returns the number of failures.
fn ecdhEs(arena: std.mem.Allocator, io: std.Io, random: std.Random, total: *usize) !usize {
    const cwd = std.Io.Dir.cwd();
    var failures: usize = 0;
    const digests = [_]xmlenc.OaepDigest{ .sha1, .sha256, .sha384, .sha512 };
    const parties = [_][2][]const u8{ .{ "", "" }, .{ "Alice", "Bob" }, .{ "", "only-v" }, .{ "only-u", "" } };
    for (curves) |c| {
        const key_path = try arena.print("{s}/ec-{s}.pem", .{ work_dir, c.openssl_name });
        const gen = try run(arena, io, &.{ "openssl", "ecparam", "-name", c.openssl_name, "-genkey", "-noout", "-out", key_path });
        if (!ok(gen)) return error.OpensslFailed;
        const text = (try run(arena, io, &.{ "openssl", "ec", "-in", key_path, "-noout", "-text" })).stdout;
        const point = try dumpBetween(arena, text, "pub:", "ASN1 OID");
        const pk = try xmlenc.EcPublicKey.fromCoordinates(c.curve, point[1..][0..c.width], point[1 + c.width ..][0..c.width]);

        for (digests, 0..) |digest, di| {
            for (parties, 0..) |party, pi| {
                for ([_]u16{ 128, 192, 256 }) |wrap| {
                    total.* += 1;
                    const content: xmlenc.ContentEnc = if ((di + pi) % 2 == 0) .aes256_gcm else .aes128_cbc;
                    const plain = "<a:Doc xmlns:a=\"urn:example:doc\">ecdh-es</a:Doc>";
                    const doc = try xmlenc.encryptData(arena, plain, .{ .ecdh_es = .{
                        .recipient = pk,
                        .wrap_bits = wrap,
                        .digest = digest,
                        .party_u_info = party[0],
                        .party_v_info = party[1],
                        .recipient_key_name = "recipient",
                    } }, random, .{ .content = content });
                    const label = try arena.print("ecdh-es/{s}/{s}/kw{d}/{d}", .{ c.openssl_name, @tagName(digest), wrap, pi });

                    // xmlsec1 finds the originator key by name: swap the ECKeyValue for a key name and give it the
                    // ephemeral public key as a PEM named `originator`.
                    const key_open = "<dsig11:PublicKey>";
                    const at = (std.mem.find(u8, doc, key_open) orelse return error.NoPoint) + key_open.len;
                    const end = std.mem.findPos(u8, doc, at, "</dsig11:PublicKey>") orelse return error.NoPoint;
                    const eph_point = try arena.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(doc[at..end]));
                    try std.base64.standard.Decoder.decode(eph_point, doc[at..end]);
                    const kv_open = "<ds:KeyValue>";
                    const kv_close = "</ds:KeyValue>";
                    const kv_at = std.mem.find(u8, doc, kv_open) orelse return error.NoPoint;
                    const kv_end = (std.mem.find(u8, doc, kv_close) orelse return error.NoPoint) + kv_close.len;
                    const named = try std.mem.concat(arena, u8, &.{ doc[0..kv_at], "<ds:KeyName>originator</ds:KeyName>", doc[kv_end..] });

                    var spki: std.ArrayList(u8) = .empty;
                    const prefix = try arena.alloc(u8, c.spki_prefix_hex.len / 2);
                    _ = try std.fmt.hexToBytes(prefix, c.spki_prefix_hex);
                    try spki.appendSlice(arena, prefix);
                    try spki.appendSlice(arena, eph_point);
                    const b64 = try arena.alloc(u8, std.base64.standard.Encoder.calcSize(spki.items.len));
                    _ = std.base64.standard.Encoder.encode(b64, spki.items);
                    var pem: std.Io.Writer.Allocating = .init(arena);
                    try pem.writer.writeAll("-----BEGIN PUBLIC KEY-----\n");
                    var off: usize = 0;
                    while (off < b64.len) : (off += 64) try pem.writer.print("{s}\n", .{b64[off..@min(off + 64, b64.len)]});
                    try pem.writer.writeAll("-----END PUBLIC KEY-----\n");
                    const pub_path = try arena.print("{s}/ephemeral-{d}.pem", .{ work_dir, total.* });
                    const doc_path = try arena.print("{s}/ecdh-{d}.xml", .{ work_dir, total.* });
                    try cwd.writeFile(io, .{ .sub_path = pub_path, .data = pem.written() });
                    try cwd.writeFile(io, .{ .sub_path = doc_path, .data = named });

                    const res = try run(arena, io, &.{ "xmlsec1", "--decrypt", "--pubkey-pem:originator", pub_path, "--privkey-pem:recipient", key_path, doc_path });
                    var out = std.mem.trim(u8, res.stdout, " \r\n");
                    if (std.mem.startsWith(u8, out, "<?xml")) out = std.mem.trim(u8, out[(std.mem.find(u8, out, "?>") orelse 0) + 2 ..], " \r\n");
                    if (!(ok(res) and std.mem.eql(u8, out, plain))) {
                        failures += 1;
                        std.debug.print("interop-xmlenc: {s}: MISMATCH\n  err {s}\n", .{ label, res.stderr });
                    }
                }
            }
        }
    }
    return failures;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);

    const ver = run(arena, io, &.{ "xmlsec1", "--version" }) catch {
        std.debug.print("interop-xmlenc: xmlsec1 not found\n", .{});
        return 2;
    };
    std.debug.print("interop-xmlenc: {s}", .{ver.stdout});

    // A fresh 2048-bit RSA key from openssl; the public half goes to `encryptData` as (n, e).
    const key_path = work_dir ++ "/key.pem";
    const gen = run(arena, io, &.{ "openssl", "genrsa", "-out", key_path, "2048" }) catch {
        std.debug.print("interop-xmlenc: openssl not found\n", .{});
        return 2;
    };
    if (!ok(gen)) return 1;
    const modulus_out = try run(arena, io, &.{ "openssl", "rsa", "-in", key_path, "-noout", "-modulus" });
    const hex_n = std.mem.trim(u8, modulus_out.stdout, " \r\n");
    const prefix = "Modulus=";
    if (!std.mem.startsWith(u8, hex_n, prefix)) return 1;
    var n_bytes: [256]u8 = undefined;
    const n = try std.fmt.hexToBytes(&n_bytes, hex_n[prefix.len..]);
    const pk = try rsa.PublicKey.fromBytes(n, &.{ 0x01, 0x00, 0x01 });

    var prng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x77)));
    const random = prng.random();

    var keks: [3][32]u8 = undefined;
    for (&keks) |*k| random.bytes(k);

    const element_plain = "<a:Doc xmlns:a=\"urn:example:doc\" id=\"7\"><a:Item>caf\xc3\xa9 &amp; \xe2\x82\xac</a:Item><a:Empty/></a:Doc>";
    const content_plain = "plain text content, no markup: 0123456789 \xc3\xa9\xe2\x82\xac";
    // xmlsec1 serializes the decrypted data with numeric character references for the non-ASCII characters.
    const element_expected = "<a:Doc xmlns:a=\"urn:example:doc\" id=\"7\"><a:Item>caf&#xE9; &amp; &#x20AC;</a:Item><a:Empty/></a:Doc>";
    const content_expected = "plain text content, no markup: 0123456789 &#xE9;&#x20AC;";
    const contents = [_]xmlenc.ContentEnc{ .aes128_cbc, .aes192_cbc, .aes256_cbc, .aes128_gcm, .aes192_gcm, .aes256_gcm };

    const Delivery = struct { name: []const u8, key: xmlenc.EncryptKey, kek: ?[]const u8 };
    const deliveries = [_]Delivery{
        .{ .name = "oaep-sha1", .key = .{ .rsa_oaep = .{ .key = pk, .digest = .sha1, .mgf = .sha1 } }, .kek = null },
        .{ .name = "oaep-sha256", .key = .{ .rsa_oaep = .{ .key = pk } }, .kek = null },
        .{ .name = "oaep-sha384-mgf1sha1", .key = .{ .rsa_oaep = .{ .key = pk, .digest = .sha384, .mgf = .sha1 } }, .kek = null },
        .{ .name = "oaep-sha512", .key = .{ .rsa_oaep = .{ .key = pk, .digest = .sha512, .mgf = .sha512 } }, .kek = null },
        .{ .name = "kw-aes128", .key = .{ .aes_kw = keks[0][0..16] }, .kek = keks[0][0..16] },
        .{ .name = "kw-aes192", .key = .{ .aes_kw = keks[1][0..24] }, .kek = keks[1][0..24] },
        .{ .name = "kw-aes256", .key = .{ .aes_kw = keks[2][0..32] }, .kek = keks[2][0..32] },
    };

    var failures: usize = 0;
    var total: usize = 0;
    for (deliveries) |d| {
        for (contents) |content| {
            for ([_]bool{ true, false }) |as_element| {
                total += 1;
                const plain = if (as_element) element_plain else content_plain;
                const xml_text = try xmlenc.encryptData(arena, plain, d.key, random, .{ .content = content, .type_element = as_element });
                const label = try arena.print("{s}/{s}/{s}", .{ d.name, @tagName(content), if (as_element) "element" else "content" });
                const doc_path = try arena.print("{s}/doc-{d}.xml", .{ work_dir, total });
                try cwd.writeFile(io, .{ .sub_path = doc_path, .data = xml_text });

                var argv: std.ArrayList([]const u8) = .empty;
                // The EncryptedKey carries no KeyName / KeyInfo hint, so the one loaded key is used (xmlsec1 `--lax-key-search`).
                try argv.appendSlice(arena, &.{ "xmlsec1", "--decrypt", "--lax-key-search" });
                if (d.kek) |kek| {
                    const kek_path = try arena.print("{s}/kek-{d}.bin", .{ work_dir, kek.len });
                    try cwd.writeFile(io, .{ .sub_path = kek_path, .data = kek });
                    try argv.appendSlice(arena, &.{ "--aeskey", kek_path });
                } else {
                    try argv.appendSlice(arena, &.{ "--privkey-pem", key_path });
                }
                try argv.append(arena, doc_path);
                const res = try run(arena, io, argv.items);

                // xmlsec1 prints the decrypted data to stdout after an XML declaration, which is dropped here.
                var out = std.mem.trim(u8, res.stdout, " \r\n");
                if (std.mem.startsWith(u8, out, "<?xml")) {
                    const end = std.mem.find(u8, out, "?>") orelse 0;
                    out = std.mem.trim(u8, out[end + 2 ..], " \r\n");
                }
                const good = ok(res) and std.mem.eql(u8, out, if (as_element) element_expected else content_expected);
                if (!good) {
                    failures += 1;
                    std.debug.print("interop-xmlenc: {s}: MISMATCH (exit {any})\n  want {s}\n  got  {s}\n  err  {s}\n", .{ label, res.term, if (as_element) element_expected else content_expected, out, res.stderr });
                }
            }
        }
    }
    failures += try ecdhEs(arena, io, random, &total);
    std.debug.print("interop-xmlenc: {d} of {d} combinations decrypted by xmlsec1 to the exact plaintext\n", .{ total - failures, total });
    return if (failures == 0) 0 else 1;
}
