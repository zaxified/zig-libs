// SPDX-License-Identifier: MIT

//! The live oracle's value, kept in every test lane: `tools/interop.zig`
//! captured real clients (OpenSSL 3.5 `s_client`, Go 1.26 crypto/tls)
//! resuming tickets this module sealed, and foreign TLS 1.2 servers'
//! NewSessionTickets (`interop_vectors.zig`). Here, with no peer present:
//!   - each resuming ClientHello goes through `select.selectPsk` with the
//!     run's STEKs and clock — the client's real binder must verify (or, for
//!     a ticket under a key past its lifetime, nothing is selected), its real
//!     `obfuscated_ticket_age` must pass the freshness window, and the same
//!     ClientHello again is refused by the strike register;
//!   - a binder changed in one bit is `error.BinderMismatch`;
//!   - the 0-RTT record s_client sent opens under `EarlyDataContext` keys
//!     derived from the selected PSK and the complete ClientHello;
//!   - OpenSSL's and Go's TLS 1.2 NewSessionTicket decode and re-encode
//!     byte-exact, and the resuming client's SessionTicket extension offers
//!     exactly that ticket.

const std = @import("std");
const testing = std.testing;
const v = @import("interop_vectors.zig");
const stek = @import("stek.zig");
const select = @import("select.zig");
const replay = @import("replay.zig");
const earlydata = @import("earlydata.zig");
const ticket12 = @import("ticket12.zig");

const policy: stek.RotationPolicy = .{ .period_s = v.period_s, .lifetime_s = v.lifetime_s };
const Ring = stek.StekRing(stek.depthFor(policy));

const Sha256 = struct {
    const Hash = std.crypto.hash.sha2.Sha256;
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
};
const Sha384 = struct {
    const Hash = std.crypto.hash.sha2.Sha384;
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha384;
    const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
    const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;
};

fn ringAt(keys: usize) Ring {
    var ring: Ring = .init();
    for (v.rotations[0..keys]) |r| {
        const key: [32]u8 = @splat(v.key_fill +% r.id);
        ring.rotate(r.id, &key, r.at_s);
    }
    return ring;
}

/// The ClientHello handshake message (header included) at the start of
/// `flight`, and the offset of the record after it.
fn clientHello(buf: []u8, flight: []const u8) !struct { []const u8, usize } {
    var off: usize = 0;
    var len: usize = 0;
    while (off + 5 <= flight.len) {
        if (flight[off] != 22) return error.NotHandshake;
        const n = std.mem.readInt(u16, flight[off + 3 ..][0..2], .big);
        @memcpy(buf[len..][0..n], flight[off + 5 ..][0..n]);
        len += n;
        off += 5 + n;
        if (len >= 4 and len >= 4 + std.mem.readInt(u24, buf[1..4], .big)) break;
    }
    if (len < 4 or buf[0] != 1) return error.NoClientHello;
    const msg_len = 4 + std.mem.readInt(u24, buf[1..4], .big);
    if (len != msg_len) return error.ClientHelloSpansRecords;
    return .{ buf[0..msg_len], off };
}

/// The `pre_shared_key` extension (RFC 8446 §4.2.11, the last one) of a
/// ClientHello message: its data.
fn pskExtension(ch: []const u8) ![]const u8 {
    var off: usize = 4 + 2 + 32;
    off += 1 + ch[off];
    off += 2 + std.mem.readInt(u16, ch[off..][0..2], .big);
    off += 1 + ch[off];
    const end = off + 2 + std.mem.readInt(u16, ch[off..][0..2], .big);
    if (end != ch.len) return error.TrailingOctets;
    off += 2;
    var last: ?[]const u8 = null;
    while (off + 4 <= end) {
        const t = std.mem.readInt(u16, ch[off..][0..2], .big);
        const n = std.mem.readInt(u16, ch[off + 2 ..][0..2], .big);
        last = if (t == 41) ch[off + 4 ..][0..n] else null;
        off += 4 + n;
    }
    return last orelse error.NoPreSharedKeyLast;
}

fn Offer(comptime mac_len: usize) type {
    return struct {
        ids: [4]select.OfferedIdentity = undefined,
        binders: [4][mac_len]u8 = undefined,
        n: usize = 0,
        /// Octets at the end of the ClientHello the binder does not cover.
        binders_len: usize = 0,
    };
}

fn parseOffer(comptime mac_len: usize, ext: []const u8) !Offer(mac_len) {
    var o: Offer(mac_len) = .{};
    const ids_len = std.mem.readInt(u16, ext[0..2], .big);
    var off: usize = 2;
    while (off < 2 + ids_len) {
        const n = std.mem.readInt(u16, ext[off..][0..2], .big);
        o.ids[o.n] = .{ .ticket = ext[off + 2 ..][0..n], .obfuscated_ticket_age = std.mem.readInt(u32, ext[off + 2 + n ..][0..4], .big) };
        o.n += 1;
        off += 2 + n + 4;
    }
    o.binders_len = ext.len - off;
    if (std.mem.readInt(u16, ext[off..][0..2], .big) != o.binders_len - 2) return error.BadBinders;
    off += 2;
    var i: usize = 0;
    while (off < ext.len) : (i += 1) {
        if (ext[off] != mac_len) return error.BadBinderLength;
        o.binders[i] = ext[off + 1 ..][0..mac_len].*;
        off += 1 + mac_len;
    }
    if (i != o.n) return error.BindersDoNotAlign;
    return o;
}

fn replayOne(comptime S: type, r: v.Resumption) !void {
    const mac_len = S.Hmac.mac_length;
    var ch_buf: [1 << 14]u8 = undefined;
    const ch, const after = try clientHello(&ch_buf, r.flight);
    var o = try parseOffer(mac_len, try pskExtension(ch));

    var empty_hash: [S.Hash.digest_length]u8 = undefined;
    S.Hash.hash("", &empty_hash, .{});
    var truncated_hash: [S.Hash.digest_length]u8 = undefined;
    S.Hash.hash(ch[0 .. ch.len - o.binders_len], &truncated_hash, .{});

    const ring = ringAt(r.keys);
    var strike: replay.StrikeRegister = .init(testing.allocator, 8, 60_000);
    defer strike.deinit();
    var scratch: [4096]u8 = undefined;
    var sel: select.Selection(S.Hkdf.prk_length) = undefined;
    const got = select.selectPsk(S.Hkdf, S.Hmac, Ring, &sel, &ring, policy, o.ids[0..o.n], o.binders[0..o.n], &empty_hash, &truncated_hash, r.now_ms, r.freshness_ms, if (r.freshness_ms != null) &strike else null, null, &scratch);
    if (!r.resumed) return testing.expectError(error.NoAcceptableIdentity, got);
    try got;
    try testing.expectEqual(@as(usize, 0), sel.selected_index);

    if (r.freshness_ms != null) {
        // The client's own age, from its obfuscated_ticket_age: small, as the
        // server's simulated clock did not move.
        const age = replay.deobfuscateAge(o.ids[0].obfuscated_ticket_age, sel.session.ticket_age_add);
        try testing.expect(age < 10_000);
        // The same ClientHello again: single use.
        var again: select.Selection(S.Hkdf.prk_length) = undefined;
        try testing.expectError(error.NoAcceptableIdentity, select.selectPsk(S.Hkdf, S.Hmac, Ring, &again, &ring, policy, o.ids[0..o.n], o.binders[0..o.n], &empty_hash, &truncated_hash, r.now_ms, r.freshness_ms, &strike, null, &scratch));
    } else {
        // A rotation case: the same ticket once its key is past the lifetime.
        const key_at = v.rotations[0].at_s;
        try testing.expectError(error.NoAcceptableIdentity, select.selectPsk(S.Hkdf, S.Hmac, Ring, &sel, &ring, policy, o.ids[0..o.n], o.binders[0..o.n], &empty_hash, &truncated_hash, (key_at + v.lifetime_s) * 1000, null, null, null, &scratch));
    }

    if (r.early) |want| {
        var full_hash: [S.Hash.digest_length]u8 = undefined;
        S.Hash.hash(ch, &full_hash, .{});
        const Ctx = earlydata.EarlyDataContext(S.Hkdf, S.Aead.key_length);
        var ctx: Ctx = undefined;
        Ctx.derive(&ctx, &sel.psk, &full_hash);
        // Skip a change_cipher_spec; the next record is the early data.
        var off = after;
        if (r.flight[off] == 20) off += 5 + std.mem.readInt(u16, r.flight[off + 3 ..][0..2], .big);
        try testing.expectEqual(@as(u8, 23), r.flight[off]);
        const len = std.mem.readInt(u16, r.flight[off + 3 ..][0..2], .big);
        const body = r.flight[off + 5 ..][0..len];
        var plain: [256]u8 = undefined;
        const ct = body[0 .. len - S.Aead.tag_length];
        // Sequence number 0: the nonce is the IV (RFC 8446 §5.3).
        try S.Aead.decrypt(plain[0..ct.len], ct, body[len - S.Aead.tag_length ..][0..S.Aead.tag_length].*, r.flight[off..][0..5], ctx.iv, ctx.key);
        // TLSInnerPlaintext: content, type application_data, zero padding.
        const inner = std.mem.trimEnd(u8, plain[0..ct.len], "\x00");
        try testing.expectEqual(@as(u8, 23), inner[inner.len - 1]);
        try testing.expectEqualStrings(want, inner[0 .. inner.len - 1]);
    }

    // One bit of the client's binder changed: the ticket opens, the binder
    // does not verify, and that is fatal.
    o.binders[0][mac_len / 2] ^= 0x01;
    try testing.expectError(error.BinderMismatch, select.selectPsk(S.Hkdf, S.Hmac, Ring, &sel, &ring, policy, o.ids[0..o.n], o.binders[0..o.n], &empty_hash, &truncated_hash, r.now_ms, null, null, null, &scratch));
}

test "interop replay: real clients' resuming ClientHellos through selectPsk (and 0-RTT through EarlyDataContext)" {
    var early_seen: usize = 0;
    var refused_seen: usize = 0;
    for (v.resumptions) |r| {
        errdefer std.debug.print("case {s}\n", .{r.name});
        switch (r.suite) {
            0x1301 => try replayOne(Sha256, r),
            0x1302 => try replayOne(Sha384, r),
            else => return error.UnexpectedSuite,
        }
        if (r.early != null) early_seen += 1;
        if (!r.resumed) refused_seen += 1;
    }
    // The capture covers both hashes, both clients, 0-RTT and a key past
    // its lifetime; a re-capture that lost one of them should not pass.
    try testing.expect(early_seen >= 1 and refused_seen >= 1);
    var go = false;
    var sha256 = false;
    for (v.resumptions) |r| {
        go = go or std.mem.eql(u8, r.client, "go");
        sha256 = sha256 or r.suite == 0x1301;
    }
    try testing.expect(go and sha256);
}

test "interop replay: OpenSSL's and Go's TLS 1.2 NewSessionTicket, and the ticket the client offers back" {
    try testing.expect(v.tls12.len >= 2);
    for (v.tls12) |t| {
        errdefer std.debug.print("case {s}\n", .{t.name});
        const nst = try ticket12.NewSessionTicket12.decode(t.nst);
        try testing.expect(!nst.isWithdrawal());
        try testing.expectEqualSlices(u8, t.offered, nst.ticket);
        try testing.expectEqual(ticket12.ClientExtension.offers_ticket, ticket12.classifyClientExtension(t.offered));
        var buf: [1024]u8 = undefined;
        try testing.expectEqualSlices(u8, t.nst, try nst.encode(&buf));
        try testing.expectError(error.Malformed, ticket12.NewSessionTicket12.decode(t.nst[0 .. t.nst.len - 1]));
    }
}
