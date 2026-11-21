// SPDX-License-Identifier: MIT
//! RFC 9380 §5.3.1 `expand_message_xmd`: the uniform-bytes expander every
//! RFC 9380 hash-to-curve / hash-to-field suite over a SHA-2 hash runs
//! (BLS12-381, BN254, P-256/384/521 and ristretto255/decaf448 in RFC 9497,
//! secp256k1 in RFC 9591). One generic copy for the whole collection,
//! generic over the hash type, so `std.crypto.hash.sha2`'s types and this
//! module's (same declarations) both work.
//!
//! A DST longer than 255 bytes is first reduced to
//! `H("H2C-OVERSIZE-DST-" || DST)` (§5.3.3), as blst and RustCrypto's
//! `hash2curve` do; RFC 9380 Appendix K.2 is that case.

const std = @import("std");

/// The §5.3.3 prefix of an oversize DST's hash.
pub const oversize_dst_prefix = "H2C-OVERSIZE-DST-";

/// `expand_message_xmd(msg, DST, len_in_bytes)` (RFC 9380 §5.3.1) with
/// hash `Hash` (a Merkle–Damgård hash with std's interface: `init(.{})`,
/// `update`, `final`, `digest_length`, `block_length` — any SHA-2 type of
/// std or of this module). `msg` is given as consecutive parts
/// (`parts[0] || parts[1] || ...`, never concatenated in memory): it enters
/// only the first, streamed hash. `len_in_bytes` is comptime, so the §5.3.1
/// step-2 bounds (`len_in_bytes <= 65535`, `ell <= 255`, and here also
/// `len_in_bytes > 0`) are compile errors. A `dst` of more than 255 bytes is
/// reduced per §5.3.3; an empty `dst` is accepted (RFC 9380 §3.1 forbids
/// empty tags for a suite, which is the caller's contract).
///
/// The intermediate `b_0`/`b_i` are wiped before returning; the output is
/// the caller's.
pub fn expandMessageXmd(
    comptime Hash: type,
    comptime len_in_bytes: usize,
    parts: []const []const u8,
    dst: []const u8,
) [len_in_bytes]u8 {
    const b_in_bytes = Hash.digest_length;
    const s_in_bytes = Hash.block_length;
    const ell = comptime (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
    comptime {
        if (len_in_bytes == 0 or len_in_bytes > 65535 or ell > 255)
            @compileError("expand_message_xmd: len_in_bytes out of range");
    }

    // §5.3.3: an oversize DST is replaced by its hash.
    var reduced: [b_in_bytes]u8 = undefined;
    const tag: []const u8 = if (dst.len > 255) blk: {
        var h = Hash.init(.{});
        h.update(oversize_dst_prefix);
        h.update(dst);
        h.final(&reduced);
        break :blk &reduced;
    } else dst;
    const tag_len = [1]u8{@intCast(tag.len)}; // DST_prime = DST || I2OSP(len(DST), 1)

    const z_pad: [s_in_bytes]u8 = @splat(0);
    const l_i_b_str = [2]u8{ @intCast(len_in_bytes >> 8), @intCast(len_in_bytes & 0xff) };

    var h0 = Hash.init(.{});
    h0.update(&z_pad);
    for (parts) |part| h0.update(part);
    h0.update(&l_i_b_str);
    h0.update(&[1]u8{0x00});
    h0.update(tag);
    h0.update(&tag_len);
    var b0: [b_in_bytes]u8 = undefined;
    h0.final(&b0);

    var out: [len_in_bytes]u8 = undefined;
    var b_prev: [b_in_bytes]u8 = undefined;
    var h1 = Hash.init(.{});
    h1.update(&b0);
    h1.update(&[1]u8{0x01});
    h1.update(tag);
    h1.update(&tag_len);
    h1.final(&b_prev);
    {
        const n = @min(b_in_bytes, len_in_bytes);
        @memcpy(out[0..n], b_prev[0..n]);
    }
    comptime var i: usize = 2;
    inline while (i <= ell) : (i += 1) {
        var xored: [b_in_bytes]u8 = undefined;
        for (&xored, b0, b_prev) |*o, x, y| o.* = x ^ y;
        var hi = Hash.init(.{});
        hi.update(&xored);
        hi.update(&[1]u8{@intCast(i)});
        hi.update(tag);
        hi.update(&tag_len);
        hi.final(&b_prev);
        const offset = (i - 1) * b_in_bytes;
        const n = @min(b_in_bytes, len_in_bytes - offset);
        @memcpy(out[offset..][0..n], b_prev[0..n]);
    }
    std.crypto.secureZero(u8, &b0);
    std.crypto.secureZero(u8, &b_prev);
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const root = @import("root.zig");

const Vec = struct { msg: []const u8, len: usize, hex: []const u8 };

/// RFC 9380 Appendix K.1, `expand_message_xmd(SHA-256)`.
const k1_dst = "QUUX-V01-CS02-with-expander-SHA256-128";
const k1 = [_]Vec{
    .{ .msg = "", .len = 0x20, .hex = "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235" },
    .{ .msg = "abc", .len = 0x20, .hex = "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615" },
    .{ .msg = "abcdef0123456789", .len = 0x20, .hex = "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .len = 0x20, .hex = "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9" },
    .{ .msg = "a512_" ++ @as([512]u8, @splat('a')), .len = 0x20, .hex = "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c" },
    .{ .msg = "", .len = 0x80, .hex = "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced" },
    .{ .msg = "abc", .len = 0x80, .hex = "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40" },
    .{ .msg = "abcdef0123456789", .len = 0x80, .hex = "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .len = 0x80, .hex = "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a" },
};

/// RFC 9380 Appendix K.2, `expand_message_xmd(SHA-256)` with a 256-byte DST.
const k2_dst = "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-" ++ @as([208]u8, @splat('1'));
const k2 = [_]Vec{
    .{ .msg = "", .len = 0x20, .hex = "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3" },
    .{ .msg = "abc", .len = 0x20, .hex = "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12" },
    .{ .msg = "abcdef0123456789", .len = 0x20, .hex = "35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .len = 0x20, .hex = "01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc" },
    .{ .msg = "a512_" ++ @as([512]u8, @splat('a')), .len = 0x20, .hex = "20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b" },
    .{ .msg = "", .len = 0x80, .hex = "14604d85432c68b757e485c8894db3117992fc57e0e136f71ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5ce4f7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d5edbd873f0eb35260145cd4e64f748c5dfe60567e126604bcab1a3ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc" },
    .{ .msg = "abc", .len = 0x80, .hex = "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267" },
    .{ .msg = "abcdef0123456789", .len = 0x80, .hex = "d2ecef3635d2397f34a9f86438d772db19ffe9924e28a1caf6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33a4249206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d7027ed3774512ef5b00d816e51bfcc96c3539601fa48ef1c07e494bdc37054ba96ecb9dbd666417e3de289d4f424f502a982" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .len = 0x80, .hex = "ed6e8c036df90111410431431a232d41a32c86e296c05d426e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9180d0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c50e3a83316783b649e5ecc9d3b1d9471cb5024b7ccf40d41d1751a04ca0356548bc6e703fca02ab521b505e8e45600508d32" },
};

/// RFC 9380 Appendix K.3, `expand_message_xmd(SHA-512)`.
const k3_dst = "QUUX-V01-CS02-with-expander-SHA512-256";
const k3 = [_]Vec{
    .{ .msg = "", .len = 0x20, .hex = "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba" },
    .{ .msg = "abc", .len = 0x20, .hex = "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc" },
    .{ .msg = "abcdef0123456789", .len = 0x20, .hex = "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .len = 0x20, .hex = "7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3" },
    .{ .msg = "a512_" ++ @as([512]u8, @splat('a')), .len = 0x20, .hex = "57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4" },
    .{ .msg = "", .len = 0x80, .hex = "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961" },
    .{ .msg = "abc", .len = 0x80, .hex = "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1" },
    .{ .msg = "abcdef0123456789", .len = 0x80, .hex = "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac" },
    .{ .msg = "q128_" ++ @as([128]u8, @splat('q')), .len = 0x80, .hex = "b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed" },
};

fn expectVectors(comptime Hash: type, comptime vectors: []const Vec, dst: []const u8) !void {
    inline for (vectors) |v| {
        var want: [v.len]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, v.hex);
        try testing.expectEqualSlices(u8, &want, &expandMessageXmd(Hash, v.len, &.{v.msg}, dst));
    }
}

test "RFC 9380 K.1: SHA-256, len 0x20 and 0x80 (std's and this module's Sha256)" {
    try testing.expectEqual(@as(usize, 38), k1_dst.len);
    try expectVectors(std.crypto.hash.sha2.Sha256, &k1, k1_dst);
    try expectVectors(root.Sha256, &k1, k1_dst);
}

test "RFC 9380 K.2: SHA-256 with a 256-byte DST (§5.3.3 reduction)" {
    try testing.expectEqual(@as(usize, 256), k2_dst.len);
    try expectVectors(std.crypto.hash.sha2.Sha256, &k2, k2_dst);
    try expectVectors(root.Sha256, &k2, k2_dst);
}

test "RFC 9380 K.3: SHA-512, len 0x20 and 0x80 (std's and this module's Sha512)" {
    try testing.expectEqual(@as(usize, 38), k3_dst.len);
    try expectVectors(std.crypto.hash.sha2.Sha512, &k3, k3_dst);
    try expectVectors(root.Sha512, &k3, k3_dst);
}

test "a long DST equals its reduced form; 255 bytes is not reduced" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var reduced: [32]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(oversize_dst_prefix);
    h.update(k2_dst);
    h.final(&reduced);
    try testing.expectEqualSlices(u8, &expandMessageXmd(Sha256, 48, &.{"m"}, &reduced), &expandMessageXmd(Sha256, 48, &.{"m"}, k2_dst));
    // 255 bytes stays the tag itself: differs from its own reduction.
    const d255 = k2_dst[0..255];
    h = Sha256.init(.{});
    h.update(oversize_dst_prefix);
    h.update(d255);
    h.final(&reduced);
    try testing.expect(!std.mem.eql(u8, &expandMessageXmd(Sha256, 48, &.{"m"}, &reduced), &expandMessageXmd(Sha256, 48, &.{"m"}, d255)));
}

test "parts are the concatenated message; ell = 255 and a partial last block" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const whole = expandMessageXmd(Sha256, 100, &.{"abcdef0123456789"}, k1_dst);
    try testing.expectEqualSlices(u8, &whole, &expandMessageXmd(Sha256, 100, &.{ "abc", "", "def0123", "456789" }, k1_dst));
    try testing.expectEqualSlices(u8, &whole, &expandMessageXmd(Sha256, 100, &.{ "", "abcdef0123456789" }, k1_dst));
    // A shorter output is NOT a prefix of a longer one (len_in_bytes enters b_0).
    const short = expandMessageXmd(Sha256, 32, &.{"abcdef0123456789"}, k1_dst);
    try testing.expect(!std.mem.eql(u8, &short, whole[0..32]));
    // The largest SHA-256 output (ell = 255) against an empty DST.
    const max = expandMessageXmd(Sha256, 255 * 32, &.{"x"}, "");
    try testing.expect(!std.mem.allEqual(u8, max[255 * 32 - 32 ..], 0));
}
