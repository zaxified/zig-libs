// SPDX-License-Identifier: MIT

//! What a consumer can do with `ssh`'s wire layer entirely off the socket:
//! build our own SSH_MSG_KEXINIT the way `Transport.clientHandshake` does,
//! frame it through the RFC 4253 §6 Binary Packet Protocol, "receive" it back
//! out of the same in-memory buffer, and decode it — then do the same for an
//! RFC 8308 SSH_MSG_EXT_INFO carrying `server-sig-algs` and pick a publickey
//! algorithm from it. This is the offline half of a handshake: no socket, no
//! key exchange, no host-key crypto, just the framing and negotiation
//! bookkeeping a caller might replay from a packet capture or a test fixture.
//!
//! Built against the PUBLISHED module (`@import("ssh")`) only. The big
//! interactive client+server demo lives in `example-apps/ssh-demo` instead —
//! this file stays small and deterministic on purpose (CONVENTIONS.md §7.2).

const std = @import("std");
const ssh = @import("ssh");
const transport = ssh.transport;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── build our own KEXINIT the way clientHandshake does ─────────────────
    //
    // `offeredKexAlgorithms` appends the RFC 8308 §2.1 `ext-info-c` indicator
    // to the module's own `kex_algorithms` list — that is what tells a peer
    // this side is prepared to receive an SSH_MSG_EXT_INFO.
    var kex_buf: [transport.kex_algorithms.len + 1][]const u8 = undefined;
    const offered_kex = transport.offeredKexAlgorithms(&kex_buf, .client);

    const cookie: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const sent: transport.KexInit = .{
        .cookie = cookie,
        .kex_algorithms = offered_kex,
        .server_host_key_algorithms = &transport.server_host_key_algorithms,
        .encryption_algorithms_client_to_server = &transport.encryption_algorithms,
        .encryption_algorithms_server_to_client = &transport.encryption_algorithms,
        .mac_algorithms_client_to_server = &transport.mac_algorithms,
        .mac_algorithms_server_to_client = &transport.mac_algorithms,
        .compression_algorithms_client_to_server = &transport.compression_algorithms,
        .compression_algorithms_server_to_client = &transport.compression_algorithms,
        .languages_client_to_server = &.{},
        .languages_server_to_client = &.{},
        .first_kex_packet_follows = false,
        .reserved = 0,
    };

    var payload_buf: [1024]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&payload_buf);
    try sent.encode(&pw);

    // Frame it through the Binary Packet Protocol exactly as the plaintext
    // pre-NEWKEYS phase does (`CipherState.none`), into an in-memory "wire".
    var wire_buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wire_buf);
    var write_cipher: transport.CipherState = .none;
    try transport.writePacket(&w, &write_cipher, pw.buffered());

    // "Receive" it back out of the same bytes, the way a peer would off a
    // real socket.
    var r: std.Io.Reader = .fixed(w.buffered());
    var read_cipher: transport.CipherState = .none;
    var rbuf: [2048]u8 = undefined;
    const pkt = try transport.readPacket(&r, &read_cipher, &rbuf);
    std.debug.print("KEXINIT framed as {d}-byte packet, {d}-byte payload\n", .{ pkt.packet_length, pkt.payload.len });

    // `decode` expects the message-type byte already consumed by the caller.
    var pr: std.Io.Reader = .fixed(pkt.payload[1..]);
    var got = try transport.KexInit.decode(gpa, &pr);
    defer got.deinit(gpa);

    if (!std.mem.eql(u8, &got.cookie, &cookie)) return error.CookieMismatch;
    if (!transport.offersExtInfo(got.kex_algorithms, transport.ext_info_c)) {
        return error.ExtInfoIndicatorLost;
    }
    std.debug.print(
        "round-tripped KEXINIT: {d} kex algorithms, ext-info-c present, cookie intact\n",
        .{got.kex_algorithms.len},
    );

    // ── RFC 8308 SSH_MSG_EXT_INFO: server-sig-algs round trip ──────────────
    const server_offered = [_][]const u8{ "rsa-sha2-512", "ssh-ed25519" };
    var ext_payload_buf: [256]u8 = undefined;
    var ew: std.Io.Writer = .fixed(&ext_payload_buf);
    try transport.encodeServerSigAlgs(&ew, &server_offered);
    const ext_payload = ew.buffered();

    var ext_wire_buf: [512]u8 = undefined;
    var eww: std.Io.Writer = .fixed(&ext_wire_buf);
    var ext_write_cipher: transport.CipherState = .none;
    try transport.writePacket(&eww, &ext_write_cipher, ext_payload);

    var er: std.Io.Reader = .fixed(eww.buffered());
    var ext_read_cipher: transport.CipherState = .none;
    var erbuf: [512]u8 = undefined;
    const ext_pkt = try transport.readPacket(&er, &ext_read_cipher, &erbuf);

    const parsed = (try transport.parseExtInfo(ext_pkt.payload)) orelse
        return error.MissingServerSigAlgs;

    // Our preference order differs from the server's advertised order —
    // `pick` must honor OUR order, the caller's, not the peer's.
    const our_preference = [_][]const u8{ "ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256" };
    const picked = parsed.pick(&our_preference) orelse return error.NoAcceptableAlgorithm;
    std.debug.print("negotiated publickey algorithm: {s}\n", .{picked});
    if (!std.mem.eql(u8, picked, "ssh-ed25519")) return error.UnexpectedPick;

    // A candidate list the server accepts none of must come back null, not
    // silently pick something.
    const unsupported = [_][]const u8{"ecdsa-sha2-nistp384"};
    if (parsed.pick(&unsupported) != null) return error.PickShouldHaveFailed;

    // ── error handling by name: a truncated EXT_INFO must not panic ────────
    //
    // Keep only the message-type byte and the 4-byte extension count; every
    // extension name/value string that should follow is gone, so the first
    // `Cursor.string()` inside `parseExtInfo` runs out of bytes.
    const truncated = ext_payload[0..5];
    if (transport.parseExtInfo(truncated)) |_| {
        return error.TruncatedExtInfoShouldHaveFailed;
    } else |err| switch (err) {
        error.ProtocolError => std.debug.print("truncated EXT_INFO correctly rejected: error.ProtocolError\n", .{}),
        else => return err,
    }
}
