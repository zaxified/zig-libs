// SPDX-License-Identifier: MIT

//! SSH-2.0 client transport layer (RFC 4253) — part 1 of a larger eventual
//! `ssh` module (userauth/RFC 4252 and channels/RFC 4254 are later parts,
//! stubbed in `root.zig` but not implemented here).
//!
//! Implements: version exchange (§4.2), KEXINIT negotiation (§7.1),
//! curve25519-sha256 (RFC 8731) key exchange, the RFC 4253 §6 Binary Packet
//! Protocol, RFC 4253 §7.2 key derivation, and the two ciphers
//! `chacha20-poly1305@openssh.com` (OpenSSH `PROTOCOL.chacha20poly1305`) and
//! `aes256-ctr` + `hmac-sha2-256`. Clean-room from the RFCs; crypto from
//! `std.crypto` plus the sibling `rsa` module for `rsa-sha2-*` host keys.
//!
//! Transport-agnostic by design (same shape as the sibling `opcua` module's
//! `Connection`): `Transport.init` takes an already-connected
//! `std.Io.Reader`/`std.Io.Writer` pair — this module never opens a socket
//! itself.

const std = @import("std");
const builtin = @import("builtin");
const messages = @import("messages.zig");
const rsa = @import("rsa");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Aes256 = std.crypto.core.aes.Aes256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const ChaCha = std.crypto.stream.chacha.ChaCha20With64BitNonce;
const Poly1305 = std.crypto.onetimeauth.Poly1305;
const Hmac = std.crypto.auth.hmac.Hmac(Sha256);

/// The sibling `rsa` module's public-key type — referenced here so a
/// `HostKeyVerifier` implementation (or the eventual `curve25519Kex` body)
/// can parse an `rsa-sha2-*` host key with `rsa.PublicKey.fromBytes` and
/// verify its signature with `rsa.verifyPkcs1v15`, per RFC 8332.
pub const RsaPublicKey = rsa.PublicKey;

pub const TransportError = std.Io.Reader.Error || std.Io.Writer.Error ||
    std.mem.Allocator.Error || error{
    ProtocolError,
    VersionExchangeFailed,
    KexFailed,
    HostKeyVerificationFailed,
    UnsupportedAlgorithm,
    MacVerificationFailed,
    PacketTooLarge,
    StringTooLarge,
};

/// Our identification `softwareversion` (RFC 4253 §4.2).
pub const software_version = "zig_ssh_0.1";

// ── algorithm name-lists (RFC 4253 §7.1 negotiation; RFC 8731 curve25519) ──

/// KEX methods this client offers, most-preferred first.
///
/// `mlkem768x25519-sha256` (OpenSSH `PROTOCOL`, draft-kampanakis-curdle-ssh-
/// pq-ke — the post-quantum X25519+ML-KEM-768 hybrid, OpenSSH's current
/// default) is listed FIRST so it is what we offer by default, matching
/// OpenSSH 10.x; `curve25519-sha256` (RFC 8731) stays present right after as
/// the classical fallback. `diffie-hellman-group14-sha256` (RFC 4253 §8.1 +
/// RFC 3526 §3, SHA-256) / `diffie-hellman-group16-sha512` (RFC 3526 §5,
/// SHA-512) are the classic MODP Diffie-Hellman groups. `pickFirst`/
/// `negotiate` walk this list in order; every entry has a working KEX
/// implementation (`mlkem768x25519Kex` / `curve25519Kex` / `dhGroupKex`).
pub const kex_algorithms = [_][]const u8{
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
};

/// Host-key algorithms this client accepts for server authentication.
pub const server_host_key_algorithms = [_][]const u8{
    "ssh-ed25519",
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
};

/// Symmetric ciphers this client offers (same list both directions).
///
/// `aes256-gcm@openssh.com` / `aes128-gcm@openssh.com` (RFC 5647 + the
/// OpenSSH AES-GCM convention: the 4-byte packet-length field is AAD, not
/// encrypted; a 16-byte GCM tag replaces a separate MAC) are AEAD ciphers,
/// same as `chacha20-poly1305@openssh.com`; all install a real
/// `CipherState` variant with a working `readPacket`/`writePacket` branch.
pub const encryption_algorithms = [_][]const u8{
    "chacha20-poly1305@openssh.com",
    "aes256-ctr",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
};

/// MAC algorithms this client offers. Not used with
/// `chacha20-poly1305@openssh.com` (which is self-authenticating via
/// Poly1305) — only relevant when `aes256-ctr` (or another non-AEAD cipher)
/// is negotiated.
pub const mac_algorithms = [_][]const u8{
    "hmac-sha2-256",
};

/// Compression methods this client offers. Only `none` — this module never
/// implements compression.
pub const compression_algorithms = [_][]const u8{
    "none",
};

// ── entropy ────────────────────────────────────────────────────────────────

/// Fill `buf` with cryptographically secure random bytes from the OS. Never a
/// user-space PRNG — key material and the KEXINIT cookie depend on real
/// entropy. Panics (does not silently degrade) if the OS entropy source is
/// unavailable, matching how the rest of this repo treats a CSPRNG failure.
fn fillRandom(buf: []u8) void {
    if (builtin.os.tag != .linux)
        @compileError("fillRandom: only the Linux getrandom(2) entropy path is wired up in part 1");
    var off: usize = 0;
    while (off < buf.len) {
        const rc = std.os.linux.getrandom(buf.ptr + off, buf.len - off, 0);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            if (signed == -@as(isize, @intFromEnum(std.os.linux.E.INTR))) continue;
            @panic("getrandom failed");
        }
        off += @intCast(signed);
    }
}

// ── KEXINIT (RFC 4253 §7.1) ─────────────────────────────────────────────────

/// SSH_MSG_KEXINIT payload (RFC 4253 §7.1): the algorithm-negotiation
/// name-lists both sides exchange before key exchange proper.
pub const KexInit = struct {
    /// 16 random bytes (RFC 4253 §7.1 "cookie"), makes replaying an old
    /// KEXINIT distinguishable.
    cookie: [16]u8,
    kex_algorithms: []const []const u8,
    server_host_key_algorithms: []const []const u8,
    encryption_algorithms_client_to_server: []const []const u8,
    encryption_algorithms_server_to_client: []const []const u8,
    mac_algorithms_client_to_server: []const []const u8,
    mac_algorithms_server_to_client: []const []const u8,
    compression_algorithms_client_to_server: []const []const u8,
    compression_algorithms_server_to_client: []const []const u8,
    languages_client_to_server: []const []const u8,
    languages_server_to_client: []const []const u8,
    first_kex_packet_follows: bool,
    reserved: u32,

    /// Encode this KEXINIT as an SSH_MSG_KEXINIT payload (RFC 4253 §7.1).
    pub fn encode(self: KexInit, w: *std.Io.Writer) TransportError!void {
        try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXINIT));
        try w.writeAll(&self.cookie);
        try messages.writeNameList(w, self.kex_algorithms);
        try messages.writeNameList(w, self.server_host_key_algorithms);
        try messages.writeNameList(w, self.encryption_algorithms_client_to_server);
        try messages.writeNameList(w, self.encryption_algorithms_server_to_client);
        try messages.writeNameList(w, self.mac_algorithms_client_to_server);
        try messages.writeNameList(w, self.mac_algorithms_server_to_client);
        try messages.writeNameList(w, self.compression_algorithms_client_to_server);
        try messages.writeNameList(w, self.compression_algorithms_server_to_client);
        try messages.writeNameList(w, self.languages_client_to_server);
        try messages.writeNameList(w, self.languages_server_to_client);
        try w.writeByte(if (self.first_kex_packet_follows) 1 else 0);
        var rbuf: [4]u8 = undefined;
        std.mem.writeInt(u32, &rbuf, self.reserved, .big);
        try w.writeAll(&rbuf);
    }

    /// Decode a peer's SSH_MSG_KEXINIT payload from `r` (the message-type
    /// byte already consumed by the caller). Every name-list field is owned
    /// by `gpa`; call `deinit(gpa)` on the result.
    pub fn decode(gpa: std.mem.Allocator, r: *std.Io.Reader) TransportError!KexInit {
        var self: KexInit = undefined;
        @memcpy(&self.cookie, try r.takeArray(16));
        self.kex_algorithms = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.kex_algorithms);
        self.server_host_key_algorithms = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.server_host_key_algorithms);
        self.encryption_algorithms_client_to_server = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.encryption_algorithms_client_to_server);
        self.encryption_algorithms_server_to_client = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.encryption_algorithms_server_to_client);
        self.mac_algorithms_client_to_server = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.mac_algorithms_client_to_server);
        self.mac_algorithms_server_to_client = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.mac_algorithms_server_to_client);
        self.compression_algorithms_client_to_server = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.compression_algorithms_client_to_server);
        self.compression_algorithms_server_to_client = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.compression_algorithms_server_to_client);
        self.languages_client_to_server = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.languages_client_to_server);
        self.languages_server_to_client = try readListOwned(gpa, r);
        errdefer freeList(gpa, self.languages_server_to_client);
        self.first_kex_packet_follows = (try r.takeByte()) != 0;
        self.reserved = try r.takeInt(u32, .big);
        return self;
    }

    /// Free every name-list field (only call on a `decode`d value — a value
    /// built from the module's `const` name-lists must NOT be freed).
    pub fn deinit(self: *const KexInit, gpa: std.mem.Allocator) void {
        freeList(gpa, self.kex_algorithms);
        freeList(gpa, self.server_host_key_algorithms);
        freeList(gpa, self.encryption_algorithms_client_to_server);
        freeList(gpa, self.encryption_algorithms_server_to_client);
        freeList(gpa, self.mac_algorithms_client_to_server);
        freeList(gpa, self.mac_algorithms_server_to_client);
        freeList(gpa, self.compression_algorithms_client_to_server);
        freeList(gpa, self.compression_algorithms_server_to_client);
        freeList(gpa, self.languages_client_to_server);
        freeList(gpa, self.languages_server_to_client);
    }
};

fn readListOwned(gpa: std.mem.Allocator, r: *std.Io.Reader) TransportError![]const []const u8 {
    var nl = try messages.readNameList(gpa, r);
    defer nl.deinit();
    var names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    var it = nl.iterator();
    while (it.next()) |name| {
        if (name.len == 0) continue; // empty list -> a single "" token
        try names.append(gpa, try gpa.dupe(u8, name));
    }
    return names.toOwnedSlice(gpa);
}

fn freeList(gpa: std.mem.Allocator, list: []const []const u8) void {
    for (list) |n| gpa.free(n);
    gpa.free(list);
}

// ── version exchange (RFC 4253 §4.2) ────────────────────────────────────────

/// The `SSH-<protoversion>-<softwareversion>[ <comments>]` identification
/// string this client sends (RFC 4253 §4.2).
pub const IdentificationString = struct {
    /// Always "2.0" — this module is an SSH-2.0-only client.
    protoversion: []const u8 = "2.0",
    /// e.g. "zig-ssh_0.1".
    softwareversion: []const u8,
    comments: ?[]const u8 = null,
};

/// Exchange identification strings (RFC 4253 §4.2). Returns the peer's raw
/// `SSH-2.0-...` line (CR LF stripped), allocated via `gpa` — caller frees.
/// Tolerates and discards any non-SSH preamble lines a server sends first.
pub fn exchangeVersions(
    gpa: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    local: IdentificationString,
) TransportError![]u8 {
    try w.writeAll("SSH-");
    try w.writeAll(local.protoversion);
    try w.writeAll("-");
    try w.writeAll(local.softwareversion);
    if (local.comments) |c| {
        try w.writeAll(" ");
        try w.writeAll(c);
    }
    try w.writeAll("\r\n");
    try w.flush();

    var line: [255]u8 = undefined;
    var attempts: usize = 0;
    while (attempts < 64) : (attempts += 1) {
        var len: usize = 0;
        while (true) {
            const b = try r.takeByte();
            if (b == '\n') break;
            if (len < line.len) {
                line[len] = b;
                len += 1;
            }
        }
        var l: []const u8 = line[0..len];
        if (l.len > 0 and l[l.len - 1] == '\r') l = l[0 .. l.len - 1];
        if (std.mem.startsWith(u8, l, "SSH-")) return gpa.dupe(u8, l);
        // else: a pre-banner line — skip it (§4.2).
    }
    return error.VersionExchangeFailed;
}

// ── Binary Packet Protocol (RFC 4253 §6) ────────────────────────────────────

/// One SSH binary packet (RFC 4253 §6.1). `payload`/`padding`/`mac` are
/// slices into the caller-supplied scratch buffer passed to `readPacket`.
pub const Packet = struct {
    packet_length: u32,
    padding_length: u8,
    payload: []const u8,
    padding: []const u8,
    mac: []const u8,
};

/// `chacha20-poly1305@openssh.com` per-direction state (OpenSSH
/// `PROTOCOL.chacha20poly1305`). The 64-byte key material splits so the first
/// 32 bytes (`key_main`) key the payload+Poly1305 AEAD and the second 32
/// bytes (`key_header`) encrypt the 4-byte packet-length field; the 8-byte
/// big-endian sequence number is the per-packet ChaCha20 nonce.
pub const Chacha20Poly1305State = struct {
    key_main: [32]u8,
    key_header: [32]u8,
    /// RFC 4253 §6.4: 32-bit, wraps, never reset for the life of the direction.
    sequence_number: u32,
};

/// `aes256-ctr` + `hmac-sha2-256` (RFC 4253 §6.3 cipher, RFC 6668 MAC)
/// per-direction state. `enc_iv` is the running 128-bit CTR counter, advanced
/// one block per 16 encrypted bytes and carried across packets (never reset).
pub const Aes256CtrHmacSha256State = struct {
    enc_key: [32]u8,
    enc_iv: [16]u8,
    mac_key: [32]u8,
    /// See `Chacha20Poly1305State.sequence_number`.
    sequence_number: u32,
};

/// `aes256-gcm@openssh.com` / `aes128-gcm@openssh.com` (RFC 5647) per-
/// direction state.
///
/// `key`/`key_bits` carry up to a 256-bit AES-GCM key (`key_bits` says how
/// many of `key`'s leading bytes are the real aes128-gcm key vs the full
/// aes256-gcm key). `fixed_iv` is the 4-byte fixed part of the RFC 5647 §7.1
/// 12-byte GCM nonce (`fixed_iv || 8-byte invocation_counter`); the
/// `invocation_counter` increments once per packet, and unlike
/// `chacha20_poly1305`/`aes256_ctr_hmac_sha256` it is NOT the SSH sequence
/// number (RFC 5647 keeps them as two separate 64-bit/32-bit counters that
/// happen to increment in lockstep).
pub const AesGcmState = struct {
    key: [32]u8,
    key_bits: enum { aes128, aes256 },
    fixed_iv: [4]u8,
    invocation_counter: u64,
    /// See `Chacha20Poly1305State.sequence_number`.
    sequence_number: u32,
};

/// Active per-direction cipher/MAC state a `readPacket`/`writePacket` call is
/// keyed on. `.none` is what the plaintext KEX phase uses; a real variant is
/// installed once `Transport.clientHandshake` completes NEWKEYS.
pub const CipherState = union(enum) {
    none,
    chacha20_poly1305: Chacha20Poly1305State,
    aes256_ctr_hmac_sha256: Aes256CtrHmacSha256State,
    /// `aes256-gcm@openssh.com` / `aes128-gcm@openssh.com` — see `AesGcmState`.
    aes_gcm: AesGcmState,
};

/// Big-endian 8-byte ChaCha20 nonce built from a 32-bit SSH sequence number
/// (the high 4 bytes are always zero — OpenSSH `PROTOCOL.chacha20poly1305`).
fn seqNonce(seq: u32) [8]u8 {
    var n = [_]u8{0} ** 8;
    std.mem.writeInt(u32, n[4..8], seq, .big);
    return n;
}

/// AES-256-CTR keystream XOR over `data`, advancing `counter` (big-endian,
/// full 128-bit block) one step per 16-byte block consumed.
fn aesCtrXor(ctx: std.crypto.core.aes.AesEncryptCtx(Aes256), counter: *[16]u8, data: []u8) void {
    var i: usize = 0;
    while (i < data.len) : (i += 16) {
        var ks: [16]u8 = undefined;
        ctx.encrypt(&ks, counter);
        const n = @min(@as(usize, 16), data.len - i);
        for (0..n) |j| data[i + j] ^= ks[j];
        var k: usize = 16;
        while (k > 0) {
            k -= 1;
            counter[k] +%= 1;
            if (counter[k] != 0) break;
        }
    }
}

/// Read one binary packet (RFC 4253 §6.1) from `r` under `cipher`'s state,
/// decrypting and MAC-verifying as needed, into `buf`. Advances the sequence
/// number. Returned slices point into `buf`.
pub fn readPacket(r: *std.Io.Reader, cipher: *CipherState, buf: []u8) TransportError!Packet {
    switch (cipher.*) {
        .none => {
            const lenb = try r.takeArray(4);
            const pkt_len = std.mem.readInt(u32, lenb, .big);
            if (pkt_len < 1 or pkt_len > messages.max_wire_string_len) return error.ProtocolError;
            if (pkt_len > buf.len) return error.PacketTooLarge;
            try r.readSliceAll(buf[0..pkt_len]);
            const padlen = buf[0];
            if (@as(usize, padlen) + 1 > pkt_len) return error.ProtocolError;
            const payload_len = pkt_len - 1 - padlen;
            return .{
                .packet_length = pkt_len,
                .padding_length = padlen,
                .payload = buf[1 .. 1 + payload_len],
                .padding = buf[1 + payload_len .. pkt_len],
                .mac = buf[0..0],
            };
        },
        .chacha20_poly1305 => |*st| {
            const nonce = seqNonce(st.sequence_number);
            const enc_len = try r.takeArray(4);
            @memcpy(buf[0..4], enc_len);
            var declen: [4]u8 = undefined;
            ChaCha.xor(&declen, buf[0..4], 0, st.key_header, nonce);
            const pkt_len = std.mem.readInt(u32, &declen, .big);
            if (pkt_len < 1 or pkt_len > messages.max_wire_string_len) return error.ProtocolError;
            const total = 4 + @as(usize, pkt_len) + 16;
            if (total > buf.len) return error.PacketTooLarge;
            try r.readSliceAll(buf[4 .. 4 + pkt_len]);
            var tag: [16]u8 = undefined;
            try r.readSliceAll(&tag);
            var polykey: [32]u8 = undefined;
            ChaCha.stream(&polykey, 0, st.key_main, nonce);
            var expect: [16]u8 = undefined;
            Poly1305.create(&expect, buf[0 .. 4 + pkt_len], &polykey);
            if (!std.crypto.timing_safe.eql([16]u8, expect, tag)) return error.MacVerificationFailed;
            ChaCha.xor(buf[4 .. 4 + pkt_len], buf[4 .. 4 + pkt_len], 1, st.key_main, nonce);
            const padlen = buf[4];
            if (@as(usize, padlen) + 1 > pkt_len) return error.ProtocolError;
            const payload_len = pkt_len - 1 - padlen;
            @memcpy(buf[4 + pkt_len .. 4 + pkt_len + 16], &tag);
            st.sequence_number +%= 1;
            return .{
                .packet_length = pkt_len,
                .padding_length = padlen,
                .payload = buf[5 .. 5 + payload_len],
                .padding = buf[5 + payload_len .. 4 + pkt_len],
                .mac = buf[4 + pkt_len .. 4 + pkt_len + 16],
            };
        },
        .aes256_ctr_hmac_sha256 => |*st| {
            const ctx = Aes256.initEnc(st.enc_key);
            var counter = st.enc_iv;
            const b0 = try r.takeArray(16);
            @memcpy(buf[0..16], b0);
            aesCtrXor(ctx, &counter, buf[0..16]);
            const pkt_len = std.mem.readInt(u32, buf[0..4], .big);
            const total_pt = 4 + @as(usize, pkt_len);
            if (pkt_len < 12 or total_pt % 16 != 0 or pkt_len > messages.max_wire_string_len) return error.ProtocolError;
            if (total_pt + 32 > buf.len) return error.PacketTooLarge;
            if (total_pt > 16) {
                try r.readSliceAll(buf[16..total_pt]);
                aesCtrXor(ctx, &counter, buf[16..total_pt]);
            }
            var mac_recv: [32]u8 = undefined;
            try r.readSliceAll(&mac_recv);
            var mac: [32]u8 = undefined;
            var hm = Hmac.init(&st.mac_key);
            var seqb: [4]u8 = undefined;
            std.mem.writeInt(u32, &seqb, st.sequence_number, .big);
            hm.update(&seqb);
            hm.update(buf[0..total_pt]);
            hm.final(&mac);
            if (!std.crypto.timing_safe.eql([32]u8, mac, mac_recv)) return error.MacVerificationFailed;
            st.enc_iv = counter;
            st.sequence_number +%= 1;
            const padlen = buf[4];
            if (@as(usize, padlen) + 1 > pkt_len) return error.ProtocolError;
            const payload_len = pkt_len - 1 - padlen;
            @memcpy(buf[total_pt .. total_pt + 32], &mac_recv);
            return .{
                .packet_length = pkt_len,
                .padding_length = padlen,
                .payload = buf[5 .. 5 + payload_len],
                .padding = buf[5 + payload_len .. total_pt],
                .mac = buf[total_pt .. total_pt + 32],
            };
        },
        .aes_gcm => |*st| {
            // RFC 5647 + OpenSSH AES-GCM framing: the 4-byte packet-length
            // field is authenticated-but-NOT-encrypted (GCM AAD); the rest
            // (padding_length‖payload‖padding = `pkt_len` bytes) is GCM
            // ciphertext, followed by a 16-byte tag. The 12-byte nonce is
            // `fixed_iv || invocation_counter` (the counter increments once
            // per packet, independent of the SSH sequence number).
            const lenb = try r.takeArray(4);
            @memcpy(buf[0..4], lenb);
            const pkt_len = std.mem.readInt(u32, buf[0..4], .big);
            // GCM plaintext (padlen‖payload‖padding) is a whole number of
            // 16-byte blocks; the length field itself is excluded (RFC 5647).
            if (pkt_len == 0 or pkt_len % 16 != 0 or pkt_len > messages.max_wire_string_len)
                return error.ProtocolError;
            const total = 4 + @as(usize, pkt_len) + 16;
            if (total > buf.len) return error.PacketTooLarge;
            try r.readSliceAll(buf[4 .. 4 + pkt_len]);
            var tag: [16]u8 = undefined;
            try r.readSliceAll(&tag);
            var nonce: [12]u8 = undefined;
            @memcpy(nonce[0..4], &st.fixed_iv);
            std.mem.writeInt(u64, nonce[4..12], st.invocation_counter, .big);
            const ct = buf[4 .. 4 + pkt_len];
            switch (st.key_bits) {
                .aes256 => Aes256Gcm.decrypt(ct, ct, tag, buf[0..4], nonce, st.key) catch
                    return error.MacVerificationFailed,
                .aes128 => Aes128Gcm.decrypt(ct, ct, tag, buf[0..4], nonce, st.key[0..16].*) catch
                    return error.MacVerificationFailed,
            }
            st.invocation_counter +%= 1;
            st.sequence_number +%= 1;
            const padlen = buf[4];
            if (@as(usize, padlen) + 1 > pkt_len) return error.ProtocolError;
            const payload_len = pkt_len - 1 - padlen;
            @memcpy(buf[4 + pkt_len .. 4 + pkt_len + 16], &tag);
            return .{
                .packet_length = pkt_len,
                .padding_length = padlen,
                .payload = buf[5 .. 5 + payload_len],
                .padding = buf[5 + payload_len .. 4 + pkt_len],
                .mac = buf[4 + pkt_len .. 4 + pkt_len + 16],
            };
        },
    }
}

/// Write one binary packet (RFC 4253 §6.1) carrying `payload` to `w` under
/// `cipher`'s state (computing padding, encrypting, appending the MAC as
/// needed), then flush. Advances the sequence number.
pub fn writePacket(w: *std.Io.Writer, cipher: *CipherState, payload: []const u8) TransportError!void {
    var buf: [8192]u8 = undefined;
    switch (cipher.*) {
        .none => {
            const block: usize = 8;
            var padlen: usize = block - ((4 + 1 + payload.len) % block);
            if (padlen < 4) padlen += block;
            const pkt_len: u32 = @intCast(1 + payload.len + padlen);
            const total = 4 + @as(usize, pkt_len);
            if (total > buf.len) return error.PacketTooLarge;
            std.mem.writeInt(u32, buf[0..4], pkt_len, .big);
            buf[4] = @intCast(padlen);
            @memcpy(buf[5 .. 5 + payload.len], payload);
            fillRandom(buf[5 + payload.len .. total]);
            try w.writeAll(buf[0..total]);
            try w.flush();
        },
        .chacha20_poly1305 => |*st| {
            const block: usize = 8;
            var padlen: usize = block - ((1 + payload.len) % block);
            if (padlen < 4) padlen += block;
            const pkt_len: u32 = @intCast(1 + payload.len + padlen);
            const total = 4 + @as(usize, pkt_len) + 16;
            if (total > buf.len) return error.PacketTooLarge;
            const nonce = seqNonce(st.sequence_number);
            var lenbytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &lenbytes, pkt_len, .big);
            ChaCha.xor(buf[0..4], &lenbytes, 0, st.key_header, nonce);
            buf[4] = @intCast(padlen);
            @memcpy(buf[5 .. 5 + payload.len], payload);
            fillRandom(buf[5 + payload.len .. 4 + pkt_len]);
            ChaCha.xor(buf[4 .. 4 + pkt_len], buf[4 .. 4 + pkt_len], 1, st.key_main, nonce);
            var polykey: [32]u8 = undefined;
            ChaCha.stream(&polykey, 0, st.key_main, nonce);
            var tag: [16]u8 = undefined;
            Poly1305.create(&tag, buf[0 .. 4 + pkt_len], &polykey);
            @memcpy(buf[4 + pkt_len .. 4 + pkt_len + 16], &tag);
            try w.writeAll(buf[0..total]);
            try w.flush();
            st.sequence_number +%= 1;
        },
        .aes256_ctr_hmac_sha256 => |*st| {
            const block: usize = 16;
            var padlen: usize = block - ((4 + 1 + payload.len) % block);
            if (padlen < 4) padlen += block;
            const pkt_len: u32 = @intCast(1 + payload.len + padlen);
            const total_pt = 4 + @as(usize, pkt_len);
            if (total_pt + 32 > buf.len) return error.PacketTooLarge;
            std.mem.writeInt(u32, buf[0..4], pkt_len, .big);
            buf[4] = @intCast(padlen);
            @memcpy(buf[5 .. 5 + payload.len], payload);
            fillRandom(buf[5 + payload.len .. total_pt]);
            var mac: [32]u8 = undefined;
            var hm = Hmac.init(&st.mac_key);
            var seqb: [4]u8 = undefined;
            std.mem.writeInt(u32, &seqb, st.sequence_number, .big);
            hm.update(&seqb);
            hm.update(buf[0..total_pt]);
            hm.final(&mac);
            const ctx = Aes256.initEnc(st.enc_key);
            aesCtrXor(ctx, &st.enc_iv, buf[0..total_pt]);
            @memcpy(buf[total_pt .. total_pt + 32], &mac);
            try w.writeAll(buf[0 .. total_pt + 32]);
            try w.flush();
            st.sequence_number +%= 1;
        },
        .aes_gcm => |*st| {
            // RFC 5647 + OpenSSH AES-GCM framing (see the `readPacket` branch).
            // Block-alignment excludes the (unencrypted) length field: total
            // (padlen‖payload‖padding) is a multiple of 16, padding >= 4.
            const block: usize = 16;
            var padlen: usize = block - ((1 + payload.len) % block);
            if (padlen < 4) padlen += block;
            const pkt_len: u32 = @intCast(1 + payload.len + padlen);
            const total = 4 + @as(usize, pkt_len) + 16;
            if (total > buf.len) return error.PacketTooLarge;
            std.mem.writeInt(u32, buf[0..4], pkt_len, .big); // AAD, cleartext
            buf[4] = @intCast(padlen);
            @memcpy(buf[5 .. 5 + payload.len], payload);
            fillRandom(buf[5 + payload.len .. 4 + pkt_len]);
            var nonce: [12]u8 = undefined;
            @memcpy(nonce[0..4], &st.fixed_iv);
            std.mem.writeInt(u64, nonce[4..12], st.invocation_counter, .big);
            var tag: [16]u8 = undefined;
            const pt = buf[4 .. 4 + pkt_len];
            switch (st.key_bits) {
                .aes256 => Aes256Gcm.encrypt(pt, &tag, pt, buf[0..4], nonce, st.key),
                .aes128 => Aes128Gcm.encrypt(pt, &tag, pt, buf[0..4], nonce, st.key[0..16].*),
            }
            @memcpy(buf[4 + pkt_len .. 4 + pkt_len + 16], &tag);
            try w.writeAll(buf[0..total]);
            try w.flush();
            st.invocation_counter +%= 1;
            st.sequence_number +%= 1;
        },
    }
}

// ── key exchange (RFC 8731 curve25519-sha256) ───────────────────────────────

/// Caller-supplied host-key trust policy: given the host-key type embedded in
/// the wire blob (e.g. `"ssh-ed25519"`, `"ssh-rsa"`, `"ecdsa-sha2-nistp256"`)
/// and the raw wire key blob `K_S`, returns whether to trust it. Whatever
/// known_hosts/TOFU/pinning policy backs this belongs to the caller.
pub const HostKeyVerifier = *const fn (key_type: []const u8, key_blob: []const u8) bool;

/// Largest `K`-as-hashed encoding: mpint of a 4096-bit (512-byte) DH shared
/// secret is `uint32 len || <=1 sign-pad || 512 bytes` = 517 bytes.
pub const max_k_enc_len = 520;

/// Result of a completed key exchange (RFC 4253 §8 / RFC 8731 §4): the shared
/// secret `K` and the exchange hash `H`. `H` from the *first* KEX becomes the
/// fixed session id for the connection's lifetime.
///
/// The exchange hash is up to 64 bytes so a SHA-512 KEX
/// (`diffie-hellman-group16-sha512`) fits; `hash_len` says how many bytes are
/// valid (32 for the SHA-256 KEX methods). `k_enc` holds `K` in exactly the
/// wire form fed to the exchange hash and the RFC 4253 §7.2 KDF — an mpint for
/// curve25519 / diffie-hellman, a `string` (uint32 32 || 32-byte hash) for
/// `mlkem768x25519-sha256`. If `k_enc_len == 0`, the legacy curve25519 path
/// mpint-encodes `shared_secret` on demand instead (byte-identical result).
pub const KexResult = struct {
    shared_secret: [32]u8 = [_]u8{0} ** 32,
    exchange_hash: [64]u8 = [_]u8{0} ** 64,
    hash_len: u8 = 32,
    k_enc: [max_k_enc_len]u8 = undefined,
    k_enc_len: u16 = 0,

    /// The valid `hash_len` bytes of the exchange hash `H`.
    pub fn hash(self: *const KexResult) []const u8 {
        return self.exchange_hash[0..self.hash_len];
    }

    /// Zero every secret this result carries (the shared secret and the
    /// encoded `K`). Called via `defer` once keys are derived.
    pub fn zeroize(self: *KexResult) void {
        std.crypto.secureZero(u8, &self.shared_secret);
        std.crypto.secureZero(u8, &self.k_enc);
    }
};

/// The connection's session id — the exchange hash `H` of the *first* KEX,
/// fixed for the connection's lifetime. Up to 64 bytes (a SHA-512 first KEX).
pub const SessionId = struct {
    bytes: [64]u8 = undefined,
    len: u8 = 0,

    pub fn from(h: []const u8) SessionId {
        var s = SessionId{ .len = @intCast(h.len) };
        @memcpy(s.bytes[0..h.len], h);
        return s;
    }

    pub fn slice(self: *const SessionId) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// A non-allocating cursor over an SSH wire blob (`uint32 len || bytes`).
const SliceReader = struct {
    b: []const u8,
    i: usize = 0,

    fn string(self: *SliceReader) TransportError![]const u8 {
        if (self.i + 4 > self.b.len) return error.ProtocolError;
        const len = std.mem.readInt(u32, self.b[self.i..][0..4], .big);
        self.i += 4;
        if (@as(usize, len) + self.i > self.b.len) return error.ProtocolError;
        const s = self.b[self.i .. self.i + len];
        self.i += len;
        return s;
    }
};

fn hashString(sh: *Sha256, data: []const u8) void {
    var lb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lb, @intCast(data.len), .big);
    sh.update(&lb);
    sh.update(data);
}

fn stripLeadingZeros(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and s[i] == 0) i += 1;
    return s[i..];
}

/// Encode a non-negative big-endian magnitude as an SSH mpint into `out`,
/// returning the written slice. `out` must hold `4 + magnitude.len + 1`.
fn encodeMpint(out: []u8, magnitude: []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(out);
    messages.writeMpint(&w, magnitude) catch unreachable;
    return w.buffered();
}

fn msgType(p: Packet) u8 {
    return if (p.payload.len == 0) 0 else p.payload[0];
}

/// Verify the host-key signature `sig_blob` over the exchange hash `H`,
/// dispatched by the key type in `k_s` and the algorithm string in `sig_blob`.
fn verifySignature(key_type: []const u8, k_s: []const u8, sig_blob: []const u8, h: []const u8) TransportError!void {
    var sr = SliceReader{ .b = sig_blob };
    const sig_algo = try sr.string();
    const sig_bytes = try sr.string();

    if (std.mem.eql(u8, key_type, "ssh-ed25519")) {
        var ksr = SliceReader{ .b = k_s };
        _ = try ksr.string(); // type
        const pk_bytes = try ksr.string();
        if (pk_bytes.len != 32 or sig_bytes.len != 64) return error.HostKeyVerificationFailed;
        var pub_arr: [32]u8 = undefined;
        @memcpy(&pub_arr, pk_bytes);
        var sig_arr: [64]u8 = undefined;
        @memcpy(&sig_arr, sig_bytes);
        const pk = Ed25519.PublicKey.fromBytes(pub_arr) catch return error.HostKeyVerificationFailed;
        const signature = Ed25519.Signature.fromBytes(sig_arr);
        signature.verify(h, pk) catch return error.HostKeyVerificationFailed;
    } else if (std.mem.eql(u8, key_type, "ssh-rsa")) {
        var ksr = SliceReader{ .b = k_s };
        _ = try ksr.string(); // type
        const e = try ksr.string();
        const n = try ksr.string();
        const pk = rsa.PublicKey.fromBytes(n, e) catch return error.HostKeyVerificationFailed;
        if (std.mem.eql(u8, sig_algo, "rsa-sha2-256")) {
            rsa.verifyPkcs1v15(pk, Sha256, h, sig_bytes) catch return error.HostKeyVerificationFailed;
        } else if (std.mem.eql(u8, sig_algo, "rsa-sha2-512")) {
            rsa.verifyPkcs1v15(pk, Sha512, h, sig_bytes) catch return error.HostKeyVerificationFailed;
        } else return error.UnsupportedAlgorithm;
    } else if (std.mem.eql(u8, key_type, "ecdsa-sha2-nistp256")) {
        var ksr = SliceReader{ .b = k_s };
        _ = try ksr.string(); // type
        _ = try ksr.string(); // curve name "nistp256"
        const q = try ksr.string(); // SEC1 point
        var ssr = SliceReader{ .b = sig_bytes };
        const r_m = stripLeadingZeros(try ssr.string());
        const s_m = stripLeadingZeros(try ssr.string());
        if (r_m.len > 32 or s_m.len > 32) return error.HostKeyVerificationFailed;
        var rs = [_]u8{0} ** 64;
        @memcpy(rs[32 - r_m.len .. 32], r_m);
        @memcpy(rs[64 - s_m.len .. 64], s_m);
        const pk = EcdsaP256.PublicKey.fromSec1(q) catch return error.HostKeyVerificationFailed;
        const signature = EcdsaP256.Signature.fromBytes(rs);
        signature.verify(h, pk) catch return error.HostKeyVerificationFailed;
    } else return error.UnsupportedAlgorithm;
}

/// Run the client side of curve25519-sha256 key exchange (RFC 8731):
/// SSH_MSG_KEX_ECDH_INIT (`Q_C`) → SSH_MSG_KEX_ECDH_REPLY (`K_S`, `Q_S`,
/// signature), compute `K` and `H`, verify the host key via
/// `verify_host_key`, then verify its signature over `H`.
pub fn curve25519Kex(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    cipher: *CipherState,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    verify_host_key: HostKeyVerifier,
) TransportError!KexResult {
    var seed: [32]u8 = undefined;
    fillRandom(&seed);
    defer std.crypto.secureZero(u8, &seed);
    const kp = X25519.KeyPair.generateDeterministic(seed) catch return error.KexFailed;
    const q_c = kp.public_key;

    // SSH_MSG_KEX_ECDH_INIT: byte || string Q_C.
    var ibuf: [64]u8 = undefined;
    var iw: std.Io.Writer = .fixed(&ibuf);
    iw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) catch return error.KexFailed;
    messages.writeString(&iw, &q_c) catch return error.KexFailed;
    try writePacket(w, cipher, iw.buffered());

    // SSH_MSG_KEX_ECDH_REPLY.
    var buf: [16384]u8 = undefined;
    const pkt = try readPacket(r, cipher, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY)) return error.KexFailed;

    var cur = SliceReader{ .b = pkt.payload[1..] };
    const k_s = try cur.string();
    const q_s = try cur.string();
    const sig = try cur.string();
    if (q_s.len != 32) return error.KexFailed;

    var q_s_arr: [32]u8 = undefined;
    @memcpy(&q_s_arr, q_s);
    var shared = X25519.scalarmult(kp.secret_key, q_s_arr) catch return error.KexFailed;
    defer std.crypto.secureZero(u8, &shared);

    var kmbuf: [4 + 33]u8 = undefined;
    defer std.crypto.secureZero(u8, &kmbuf);
    const k_mpint = encodeMpint(&kmbuf, &shared);

    // H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K).
    var h: [32]u8 = undefined;
    {
        var sh = Sha256.init(.{});
        hashString(&sh, client_id);
        hashString(&sh, server_id);
        hashString(&sh, client_kexinit_payload);
        hashString(&sh, server_kexinit_payload);
        hashString(&sh, k_s);
        hashString(&sh, &q_c);
        hashString(&sh, q_s);
        sh.update(k_mpint); // K, already mpint-encoded
        sh.final(&h);
    }

    var ksr = SliceReader{ .b = k_s };
    const key_type = try ksr.string();
    if (!verify_host_key(key_type, k_s)) return error.HostKeyVerificationFailed;
    try verifySignature(key_type, k_s, sig, &h);

    // Legacy path: `k_enc_len == 0` makes `buildCipher` mpint-encode
    // `shared_secret` on demand (byte-identical to the pre-widening result).
    var res = KexResult{ .shared_secret = shared, .hash_len = 32 };
    @memcpy(res.exchange_hash[0..32], &h);
    return res;
}

/// True for either negotiated curve25519 KEX name (both dispatch to
/// `curve25519Kex` — `@libssh.org` is the pre-standardization alias for the
/// same RFC 8731 algorithm, not a different one).
fn isCurve25519Kex(name: []const u8) bool {
    return std.mem.eql(u8, name, "curve25519-sha256") or
        std.mem.eql(u8, name, "curve25519-sha256@libssh.org");
}

// ── classic MODP Diffie-Hellman (RFC 4253 §8 + RFC 3526) ────────────────────

/// RFC 3526 §3 2048-bit MODP group prime (`diffie-hellman-group14-sha256`),
/// verified byte-for-byte: computed from the RFC closed form
/// `p = 2^2048 - 2^1984 - 1 + 2^64 * (floor(2^1918 * pi) + 124476)` and
/// confirmed prime + equal to the RFC 3526 §3 hex (see the module's
/// prime-bit-length tests). Generator is g = 2.
const group14_prime_hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// RFC 3526 §5 4096-bit MODP group prime (`diffie-hellman-group16-sha512`),
/// verified byte-for-byte the same way as `group14_prime_hex`
/// (`p = 2^4096 - 2^4032 - 1 + 2^64 * (floor(2^3966 * pi) + 240904)`).
/// Generator is g = 2.
const group16_prime_hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

/// Decode a compile-time hex string into a byte array.
fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(20000);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const group14_prime = hexBytes(group14_prime_hex);
const group16_prime = hexBytes(group16_prime_hex);

/// Big-endian magnitude minus one, computed at comptime (used to derive
/// `p-1` from each group's prime for the RFC 4253 §8 `1 < e,f < p-1` upper-
/// bound check below — general subtract-with-borrow, not a "decrement the
/// last byte" shortcut, so it stays correct even though these particular
/// primes happen to end in a non-zero byte).
fn decrementBigEndian(comptime n: usize, bytes: [n]u8) [n]u8 {
    var out = bytes;
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        if (out[i] != 0) {
            out[i] -= 1;
            break;
        }
        out[i] = 0xff;
    }
    return out;
}

const group14_prime_minus_1 = decrementBigEndian(group14_prime.len, group14_prime);
const group16_prime_minus_1 = decrementBigEndian(group16_prime.len, group16_prime);

/// `a >= b`, comparing two non-negative big-endian magnitudes. `b` is
/// always a caller-supplied constant with no leading zero byte (e.g.
/// `DhGroup.prime_minus_1`); `a` is expected to already be
/// `stripLeadingZeros`'d. A longer magnitude (no leading zero) is always
/// numerically larger; equal-length magnitudes compare lexicographically,
/// which is order-preserving for big-endian byte strings.
fn magnitudeGreaterOrEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return a.len > b.len;
    return std.mem.order(u8, a, b) != .lt;
}

/// RFC 3526 modulus large enough for both group14 (2048-bit) and group16
/// (4096-bit) primes.
const DhModulus = std.crypto.ff.Modulus(4096);

/// The RFC 3526 group parameters (prime + which digest the KEX method hashes
/// with) for one `diffie-hellman-group*` name. `pub` so the server-role
/// `dhGroupKexServer` (server.zig) can reuse the same primes + digest choice.
pub const DhGroup = struct {
    prime: []const u8,
    /// `prime - 1`, precomputed, for the RFC 4253 §8 `1 < e,f < p-1` upper-
    /// bound peer-value check (`magnitudeGreaterOrEqual`).
    prime_minus_1: []const u8,
    /// true → SHA-512 (group16), false → SHA-256 (group14).
    sha512: bool,

    pub fn forName(name: []const u8) ?DhGroup {
        if (std.mem.eql(u8, name, "diffie-hellman-group14-sha256"))
            return .{ .prime = &group14_prime, .prime_minus_1 = &group14_prime_minus_1, .sha512 = false };
        if (std.mem.eql(u8, name, "diffie-hellman-group16-sha512"))
            return .{ .prime = &group16_prime, .prime_minus_1 = &group16_prime_minus_1, .sha512 = true };
        return null;
    }

    /// RFC 4253 §8: `1 < v < p-1`. Rejects `v == 0`, `v == 1`, `v >= p-1`
    /// (which includes `v == p` and `v == p-1` — the degenerate residues
    /// that force a known `K` on these safe-prime groups) and `v > p`
    /// (oversized). `v` must already be `stripLeadingZeros`'d.
    pub fn rejectsDegeneratePeerValue(self: DhGroup, v: []const u8) bool {
        if (v.len == 0 or (v.len == 1 and v[0] <= 1)) return true;
        if (v.len > self.prime.len) return true;
        if (magnitudeGreaterOrEqual(v, self.prime_minus_1)) return true;
        return false;
    }
};

/// The largest DH-group prime magnitude byte length (group16, 4096-bit).
pub const dh_max_prime_len = group16_prime.len;

pub fn isDhGroupKex(name: []const u8) bool {
    return DhGroup.forName(name) != null;
}

/// `update` a big-endian magnitude as an RFC 4251 §5 mpint (uint32 len ||
/// bytes, with a leading 0x00 sign-pad byte if the top bit is set) into
/// either a SHA-256 or SHA-512 exchange-hash context.
pub fn hashMpint(comptime H: type, sh: *H, magnitude: []const u8) void {
    var mbuf: [max_k_enc_len]u8 = undefined;
    const enc = encodeMpint(&mbuf, magnitude);
    sh.update(enc);
}

pub fn hashStringH(comptime H: type, sh: *H, data: []const u8) void {
    var lb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lb, @intCast(data.len), .big);
    sh.update(&lb);
    sh.update(data);
}

/// Modular exponentiation `base^exp mod m` (constant-time, Montgomery) via
/// `std.crypto.ff`, returning the minimal big-endian magnitude in `out`.
fn dhModExp(m: DhModulus, base_be: []const u8, exp_be: []const u8, out: []u8) TransportError![]const u8 {
    const base = DhModulus.Fe.fromBytes(m, base_be, .big) catch return error.KexFailed;
    const res = m.powWithEncodedExponent(base, exp_be, .big) catch return error.KexFailed;
    var full: [DhModulus.Fe.encoded_bytes]u8 = undefined;
    res.toBytes(&full, .big) catch return error.KexFailed;
    const mag = stripLeadingZeros(&full);
    if (mag.len > out.len) return error.KexFailed;
    @memcpy(out[0..mag.len], mag);
    return out[0..mag.len];
}

/// `base^exp mod prime` for an RFC 3526 group prime, building the constant-time
/// modulus internally. `pub` for `dhGroupKexServer`'s reuse.
pub fn dhPowModPrime(prime_be: []const u8, base_be: []const u8, exp_be: []const u8, out: []u8) TransportError![]const u8 {
    const m = DhModulus.fromBytes(prime_be, .big) catch return error.KexFailed;
    return dhModExp(m, base_be, exp_be, out);
}

/// Run the client side of classic MODP Diffie-Hellman key exchange (RFC 4253
/// §8.1, RFC 3526 groups): send SSH_MSG_KEXDH_INIT (`e = g^x mod p`), receive
/// SSH_MSG_KEXDH_REPLY (`K_S`, `f = g^y mod p`, signature), compute
/// `K = f^x mod p`, and `H = HASH(V_C‖V_S‖I_C‖I_S‖K_S‖e‖f‖K)` where `e`, `f`,
/// `K` are mpints and HASH is SHA-256 (group14) or SHA-512 (group16). Then
/// verify the host key and its signature over `H`.
pub fn dhGroupKex(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    cipher: *CipherState,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    verify_host_key: HostKeyVerifier,
    kex_name: []const u8,
) TransportError!KexResult {
    const group = DhGroup.forName(kex_name) orelse return error.UnsupportedAlgorithm;
    const m = DhModulus.fromBytes(group.prime, .big) catch return error.KexFailed;
    const g = [_]u8{2};

    // Secret exponent x: a full prime-length random value (secrecy dominates;
    // constant-time modexp keeps it side-channel-safe). Never zero.
    var x: [group16_prime.len]u8 = undefined;
    const xb = x[0..group.prime.len];
    defer std.crypto.secureZero(u8, &x);
    fillRandom(xb);
    xb[0] &= 0x7f; // keep x < p (top bit clear is sufficient for these primes)
    xb[xb.len - 1] |= 1; // ensure nonzero

    // e = g^x mod p.
    var ebuf: [group16_prime.len]u8 = undefined;
    const e = try dhModExp(m, &g, xb, &ebuf);

    // SSH_MSG_KEXDH_INIT: byte || mpint e.
    var ibuf: [8 + group16_prime.len]u8 = undefined;
    var iw: std.Io.Writer = .fixed(&ibuf);
    iw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) catch return error.KexFailed;
    messages.writeMpint(&iw, e) catch return error.KexFailed;
    try writePacket(w, cipher, iw.buffered());

    // SSH_MSG_KEXDH_REPLY: byte || string K_S || mpint f || string sig.
    var buf: [16384]u8 = undefined;
    const pkt = try readPacket(r, cipher, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY)) return error.KexFailed;
    var cur = SliceReader{ .b = pkt.payload[1..] };
    const k_s = try cur.string();
    const f = try cur.string(); // mpint magnitude (leading sign-pad, if any)
    const sig = try cur.string();

    // 1 < f < p-1 (reject degenerate peer values — RFC 4253 §8. `f == p`
    // or `f == p-1` would force a known K on these safe-prime groups).
    const f_mag = stripLeadingZeros(f);
    if (group.rejectsDegeneratePeerValue(f_mag)) return error.KexFailed;

    // K = f^x mod p.
    var kbuf: [group16_prime.len]u8 = undefined;
    defer std.crypto.secureZero(u8, &kbuf);
    const k_mag = try dhModExp(m, f_mag, xb, &kbuf);

    var res = KexResult{ .hash_len = if (group.sha512) 64 else 32 };
    if (group.sha512) {
        var sh = Sha512.init(.{});
        hashStringH(Sha512, &sh, client_id);
        hashStringH(Sha512, &sh, server_id);
        hashStringH(Sha512, &sh, client_kexinit_payload);
        hashStringH(Sha512, &sh, server_kexinit_payload);
        hashStringH(Sha512, &sh, k_s);
        hashMpint(Sha512, &sh, e);
        hashMpint(Sha512, &sh, f_mag);
        hashMpint(Sha512, &sh, k_mag);
        sh.final(res.exchange_hash[0..64]);
    } else {
        var sh = Sha256.init(.{});
        hashStringH(Sha256, &sh, client_id);
        hashStringH(Sha256, &sh, server_id);
        hashStringH(Sha256, &sh, client_kexinit_payload);
        hashStringH(Sha256, &sh, server_kexinit_payload);
        hashStringH(Sha256, &sh, k_s);
        hashMpint(Sha256, &sh, e);
        hashMpint(Sha256, &sh, f_mag);
        hashMpint(Sha256, &sh, k_mag);
        sh.final(res.exchange_hash[0..32]);
    }

    // K into the result's KDF-encoding buffer as an mpint.
    {
        var kw: std.Io.Writer = .fixed(&res.k_enc);
        messages.writeMpint(&kw, k_mag) catch return error.KexFailed;
        res.k_enc_len = @intCast(kw.buffered().len);
    }

    var ksr = SliceReader{ .b = k_s };
    const key_type = try ksr.string();
    if (!verify_host_key(key_type, k_s)) return error.HostKeyVerificationFailed;
    try verifySignature(key_type, k_s, sig, res.hash());

    return res;
}

// ── post-quantum hybrid KEX (mlkem768x25519-sha256) ─────────────────────────

/// Byte lengths of the OpenSSH `mlkem768x25519-sha256` wire values (OpenSSH
/// `PROTOCOL`, draft-kampanakis-curdle-ssh-pq-ke): the client init blob is
/// `ML-KEM-768 encapsulation key || X25519 public`, the server reply blob is
/// `ML-KEM-768 ciphertext || X25519 public`.
pub const mlkem_pk_len = MLKem768.PublicKey.encoded_length; // 1184
pub const mlkem_ct_len = MLKem768.ciphertext_length; // 1088
pub const mlkem_x25519_len = 32;
pub const mlkem_cinit_len = mlkem_pk_len + mlkem_x25519_len; // 1216
pub const mlkem_sreply_len = mlkem_ct_len + mlkem_x25519_len; // 1120

pub fn isMlkemKex(name: []const u8) bool {
    return std.mem.eql(u8, name, "mlkem768x25519-sha256");
}

/// Compute the `mlkem768x25519-sha256` hybrid shared secret from the two
/// component secrets, and write it into `res.k_enc` in the exact wire form
/// OpenSSH feeds to the exchange hash and KDF: `K = SHA256(K_MLKEM ‖ K_X25519)`
/// encoded as an SSH `string` (uint32 32 || 32-byte hash) — NOT an mpint.
/// Returns the raw 32-byte `K` (for the exchange-hash string field), which is
/// the same bytes as `res.k_enc[4..]`.
pub fn mlkemSharedK(res: *KexResult, kem_shared: [32]u8, x25519_shared: [32]u8) [32]u8 {
    var k_raw: [32]u8 = undefined;
    var sh = Sha256.init(.{});
    sh.update(&kem_shared); // ML-KEM shared secret first (OpenSSH order)
    sh.update(&x25519_shared);
    sh.final(&k_raw);
    std.mem.writeInt(u32, res.k_enc[0..4], 32, .big);
    @memcpy(res.k_enc[4..36], &k_raw);
    res.k_enc_len = 36;
    return k_raw;
}

/// Run the client side of `mlkem768x25519-sha256` (OpenSSH's post-quantum
/// hybrid, its current default): generate an X25519 ephemeral keypair AND an
/// ML-KEM-768 keypair, send `KEX_ECDH_INIT` with blob
/// `C = ML-KEM_encapsulation_key(1184) ‖ X25519_pub(32)`, receive the reply's
/// blob `S = ML-KEM_ciphertext(1088) ‖ X25519_server_pub(32)`, decapsulate +
/// X25519-scalarmult to the two component secrets, then
/// `K = SHA256(K_MLKEM ‖ K_X25519)` (encoded as a `string`) and
/// `H = SHA256(V_C‖V_S‖I_C‖I_S‖K_S‖C‖S‖string(K))`. Verify the host key + sig.
pub fn mlkem768x25519Kex(
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    cipher: *CipherState,
    client_kexinit_payload: []const u8,
    server_kexinit_payload: []const u8,
    client_id: []const u8,
    server_id: []const u8,
    verify_host_key: HostKeyVerifier,
) TransportError!KexResult {
    // X25519 ephemeral.
    var x_seed: [32]u8 = undefined;
    fillRandom(&x_seed);
    defer std.crypto.secureZero(u8, &x_seed);
    const x_kp = X25519.KeyPair.generateDeterministic(x_seed) catch return error.KexFailed;

    // ML-KEM-768 keypair (we are the decapsulator; we send the encaps key).
    var kem_seed: [MLKem768.seed_length]u8 = undefined;
    fillRandom(&kem_seed);
    defer std.crypto.secureZero(u8, &kem_seed);
    const kem_kp = MLKem768.KeyPair.generateDeterministic(kem_seed) catch return error.KexFailed;
    const kem_pub = kem_kp.public_key.toBytes();

    // C = ML-KEM_encapsulation_key(1184) || X25519_pub(32).
    var cinit: [mlkem_cinit_len]u8 = undefined;
    @memcpy(cinit[0..mlkem_pk_len], &kem_pub);
    @memcpy(cinit[mlkem_pk_len..mlkem_cinit_len], &x_kp.public_key);

    // SSH_MSG_KEX_ECDH_INIT: byte || string C.
    var ibuf: [16 + mlkem_cinit_len]u8 = undefined;
    var iw: std.Io.Writer = .fixed(&ibuf);
    iw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_INIT)) catch return error.KexFailed;
    messages.writeString(&iw, &cinit) catch return error.KexFailed;
    try writePacket(w, cipher, iw.buffered());

    // SSH_MSG_KEX_ECDH_REPLY: byte || string K_S || string S || string sig.
    var buf: [16384]u8 = undefined;
    const pkt = try readPacket(r, cipher, &buf);
    if (msgType(pkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY)) return error.KexFailed;
    var cur = SliceReader{ .b = pkt.payload[1..] };
    const k_s = try cur.string();
    const s_reply = try cur.string();
    const sig = try cur.string();
    if (s_reply.len != mlkem_sreply_len) return error.KexFailed;

    // Decapsulate ML-KEM, scalarmult X25519.
    var ct: [mlkem_ct_len]u8 = undefined;
    @memcpy(&ct, s_reply[0..mlkem_ct_len]);
    var kem_shared = kem_kp.secret_key.decaps(&ct) catch return error.KexFailed;
    defer std.crypto.secureZero(u8, &kem_shared);
    var x_srv: [32]u8 = undefined;
    @memcpy(&x_srv, s_reply[mlkem_ct_len..mlkem_sreply_len]);
    var x_shared = X25519.scalarmult(x_kp.secret_key, x_srv) catch return error.KexFailed;
    defer std.crypto.secureZero(u8, &x_shared);

    var res = KexResult{ .hash_len = 32 };
    const k_raw = mlkemSharedK(&res, kem_shared, x_shared);

    // H = SHA256(V_C || V_S || I_C || I_S || K_S || C || S || string(K)).
    {
        var sh = Sha256.init(.{});
        hashString(&sh, client_id);
        hashString(&sh, server_id);
        hashString(&sh, client_kexinit_payload);
        hashString(&sh, server_kexinit_payload);
        hashString(&sh, k_s);
        hashString(&sh, &cinit);
        hashString(&sh, s_reply);
        hashString(&sh, &k_raw); // K as a string: uint32 32 || 32-byte hash
        sh.final(res.exchange_hash[0..32]);
    }

    var ksr = SliceReader{ .b = k_s };
    const key_type = try ksr.string();
    if (!verify_host_key(key_type, k_s)) return error.HostKeyVerificationFailed;
    try verifySignature(key_type, k_s, sig, res.hash());

    return res;
}

// ── key derivation (RFC 4253 §7.2) ──────────────────────────────────────────

/// Derived transport keys (RFC 4253 §7.2), sized for `aes256-ctr` +
/// `hmac-sha2-256` (16-byte IVs, 32-byte cipher keys, 32-byte MAC keys).
pub const DerivedKeys = struct {
    iv_client_to_server: [16]u8,
    iv_server_to_client: [16]u8,
    enc_key_client_to_server: [32]u8,
    enc_key_server_to_client: [32]u8,
    mac_key_client_to_server: [32]u8,
    mac_key_server_to_client: [32]u8,
};

/// RFC 4253 §7.2 KDF for one key letter: `HASH(K || H || X || session_id)`,
/// extended via `HASH(K || H || <all so far>)` to fill `out`. `k_mpint` must
/// be `K` already in mpint wire form.
fn deriveKeyBytes(out: []u8, letter: u8, k_mpint: []const u8, h: [32]u8, session_id: [32]u8) void {
    var first: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &first);
    var s = Sha256.init(.{});
    s.update(k_mpint);
    s.update(&h);
    s.update(&[_]u8{letter});
    s.update(&session_id);
    s.final(&first);
    var written: usize = @min(out.len, 32);
    @memcpy(out[0..written], first[0..written]);
    while (written < out.len) {
        var s2 = Sha256.init(.{});
        s2.update(k_mpint);
        s2.update(&h);
        s2.update(out[0..written]);
        var block: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &block);
        s2.final(&block);
        const take = @min(@as(usize, 32), out.len - written);
        @memcpy(out[written .. written + take], block[0..take]);
        written += take;
    }
}

/// RFC 4253 §7.2 key-derivation for the `aes256-ctr`/`hmac-sha2-256` key sizes
/// (letters `A`..`F`). `shared_secret` is the raw 32-byte X25519 output.
pub fn deriveKeys(shared_secret: [32]u8, exchange_hash: [32]u8, session_id: [32]u8) DerivedKeys {
    var kmbuf: [4 + 33]u8 = undefined;
    defer std.crypto.secureZero(u8, &kmbuf);
    const k_mpint = encodeMpint(&kmbuf, &shared_secret);
    var out: DerivedKeys = undefined;
    deriveKeyBytes(&out.iv_client_to_server, 'A', k_mpint, exchange_hash, session_id);
    deriveKeyBytes(&out.iv_server_to_client, 'B', k_mpint, exchange_hash, session_id);
    deriveKeyBytes(&out.enc_key_client_to_server, 'C', k_mpint, exchange_hash, session_id);
    deriveKeyBytes(&out.enc_key_server_to_client, 'D', k_mpint, exchange_hash, session_id);
    deriveKeyBytes(&out.mac_key_client_to_server, 'E', k_mpint, exchange_hash, session_id);
    deriveKeyBytes(&out.mac_key_server_to_client, 'F', k_mpint, exchange_hash, session_id);
    return out;
}

const Direction = enum { c2s, s2c };

/// RFC 4253 §7.2 KDF for one key letter, parameterized on the KEX method's
/// hash `H` (SHA-256 for most, SHA-512 for `diffie-hellman-group16-sha512`).
/// `k_enc` is `K` already in its exchange-hash wire form (mpint or string).
fn deriveKeyBytesH(comptime H: type, out: []u8, letter: u8, k_enc: []const u8, h: []const u8, session_id: []const u8) void {
    const dlen = H.digest_length;
    var first: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &first);
    var s = H.init(.{});
    s.update(k_enc);
    s.update(h);
    s.update(&[_]u8{letter});
    s.update(session_id);
    s.final(first[0..dlen]);
    var written: usize = @min(out.len, dlen);
    @memcpy(out[0..written], first[0..written]);
    while (written < out.len) {
        var s2 = H.init(.{});
        s2.update(k_enc);
        s2.update(h);
        s2.update(out[0..written]);
        var block: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &block);
        s2.final(block[0..dlen]);
        const take = @min(dlen, out.len - written);
        @memcpy(out[written .. written + take], block[0..take]);
        written += take;
    }
}

/// Derive `out` for one key letter, dispatching on the KEX method's hash width
/// (`hash_len` 32 → SHA-256, 64 → SHA-512).
fn deriveKey(out: []u8, letter: u8, k_enc: []const u8, h: []const u8, session_id: []const u8, hash_len: u8) void {
    if (hash_len == 64) {
        deriveKeyBytesH(Sha512, out, letter, k_enc, h, session_id);
    } else {
        deriveKeyBytesH(Sha256, out, letter, k_enc, h, session_id);
    }
}

/// Build the installed `CipherState` for one direction from a negotiated
/// cipher name and the KEX result, deriving exactly the needed key material.
fn buildCipher(name: []const u8, dir: Direction, kr: KexResult, sid: []const u8, seq: u32) TransportError!CipherState {
    var kmbuf: [4 + 33]u8 = undefined;
    defer std.crypto.secureZero(u8, &kmbuf);
    // K as fed to the KDF: the KEX's explicit encoding, or (legacy curve25519)
    // the mpint of the raw 32-byte shared secret.
    const k_enc = if (kr.k_enc_len > 0) kr.k_enc[0..kr.k_enc_len] else encodeMpint(&kmbuf, &kr.shared_secret);
    const h = kr.hash();
    const hl = kr.hash_len;
    if (std.mem.eql(u8, name, "chacha20-poly1305@openssh.com")) {
        var km: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &km);
        deriveKey(&km, if (dir == .c2s) 'C' else 'D', k_enc, h, sid, hl);
        return .{ .chacha20_poly1305 = .{
            .key_main = km[0..32].*,
            .key_header = km[32..64].*,
            .sequence_number = seq,
        } };
    } else if (std.mem.eql(u8, name, "aes256-ctr")) {
        var iv: [16]u8 = undefined;
        var ek: [32]u8 = undefined;
        var mk: [32]u8 = undefined;
        deriveKey(&iv, if (dir == .c2s) 'A' else 'B', k_enc, h, sid, hl);
        deriveKey(&ek, if (dir == .c2s) 'C' else 'D', k_enc, h, sid, hl);
        deriveKey(&mk, if (dir == .c2s) 'E' else 'F', k_enc, h, sid, hl);
        return .{ .aes256_ctr_hmac_sha256 = .{
            .enc_key = ek,
            .enc_iv = iv,
            .mac_key = mk,
            .sequence_number = seq,
        } };
    } else if (std.mem.eql(u8, name, "aes256-gcm@openssh.com") or
        std.mem.eql(u8, name, "aes128-gcm@openssh.com"))
    {
        // RFC 5647: the 12-byte KDF IV (letter A/B) splits into a 4-byte fixed
        // field and an 8-byte initial invocation counter.
        var iv12: [12]u8 = undefined;
        deriveKey(&iv12, if (dir == .c2s) 'A' else 'B', k_enc, h, sid, hl);
        var key: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &key);
        const is256 = std.mem.eql(u8, name, "aes256-gcm@openssh.com");
        deriveKey(key[0..if (is256) @as(usize, 32) else 16], if (dir == .c2s) 'C' else 'D', k_enc, h, sid, hl);
        return .{ .aes_gcm = .{
            .key = key,
            .key_bits = if (is256) .aes256 else .aes128,
            .fixed_iv = iv12[0..4].*,
            .invocation_counter = std.mem.readInt(u64, iv12[4..12], .big),
            .sequence_number = seq,
        } };
    }
    return error.UnsupportedAlgorithm;
}

/// First client-offered name that the server also lists (RFC 4253 §7.1).
fn pickFirst(client: []const []const u8, server: []const []const u8) ?[]const u8 {
    for (client) |c| {
        for (server) |s| {
            if (std.mem.eql(u8, c, s)) return c;
        }
    }
    return null;
}

const Negotiated = struct {
    kex: []const u8,
    host_key: []const u8,
    cipher_c2s: []const u8,
    cipher_s2c: []const u8,
};

/// True for a self-authenticating AEAD cipher (no separate negotiated MAC):
/// `chacha20-poly1305@openssh.com` and the two AES-GCM ciphers.
pub fn isAeadCipher(name: []const u8) bool {
    return std.mem.eql(u8, name, "chacha20-poly1305@openssh.com") or
        std.mem.eql(u8, name, "aes256-gcm@openssh.com") or
        std.mem.eql(u8, name, "aes128-gcm@openssh.com");
}

fn negotiate(server_kex: KexInit) TransportError!Negotiated {
    const kex = pickFirst(&kex_algorithms, server_kex.kex_algorithms) orelse return error.UnsupportedAlgorithm;
    const host_key = pickFirst(&server_host_key_algorithms, server_kex.server_host_key_algorithms) orelse return error.UnsupportedAlgorithm;
    const c2s = pickFirst(&encryption_algorithms, server_kex.encryption_algorithms_client_to_server) orelse return error.UnsupportedAlgorithm;
    const s2c = pickFirst(&encryption_algorithms, server_kex.encryption_algorithms_server_to_client) orelse return error.UnsupportedAlgorithm;
    // MAC only matters for a non-AEAD cipher; require one is agreeable then.
    if (!isAeadCipher(c2s)) {
        _ = pickFirst(&mac_algorithms, server_kex.mac_algorithms_client_to_server) orelse return error.UnsupportedAlgorithm;
    }
    if (!isAeadCipher(s2c)) {
        _ = pickFirst(&mac_algorithms, server_kex.mac_algorithms_server_to_client) orelse return error.UnsupportedAlgorithm;
    }
    return .{ .kex = kex, .host_key = host_key, .cipher_c2s = c2s, .cipher_s2c = s2c };
}

// ── Transport ────────────────────────────────────────────────────────────

/// A caller-driven SSH-2.0 client transport over an already-connected byte
/// stream. This module never opens a socket itself.
pub const Transport = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    read_cipher: CipherState = .none,
    write_cipher: CipherState = .none,
    /// Fixed for the connection's lifetime once the first KEX completes (the
    /// exchange hash `H`; up to 64 bytes for a SHA-512 first KEX).
    session_id: ?SessionId = null,

    pub fn init(reader: *std.Io.Reader, writer: *std.Io.Writer) Transport {
        return .{ .reader = reader, .writer = writer };
    }

    /// Full client handshake, in order: version exchange → KEXINIT exchange →
    /// curve25519 key exchange → key derivation → SSH_MSG_NEWKEYS both ways →
    /// install `read_cipher`/`write_cipher`. After this returns, the
    /// connection is an encrypted transport ready for userauth (part 2).
    pub fn clientHandshake(t: *Transport, gpa: std.mem.Allocator, verify_host_key: HostKeyVerifier) TransportError!void {
        const local_id = IdentificationString{ .softwareversion = software_version };
        const v_s = try exchangeVersions(gpa, t.reader, t.writer, local_id);
        defer gpa.free(v_s);
        var vcbuf: [128]u8 = undefined;
        const v_c = std.fmt.bufPrint(&vcbuf, "SSH-2.0-{s}", .{software_version}) catch unreachable;

        const scratch = try gpa.alloc(u8, 64 * 1024);
        defer gpa.free(scratch);

        // Build + send our KEXINIT (payload kept as I_C).
        var cookie: [16]u8 = undefined;
        fillRandom(&cookie);
        const empty: []const []const u8 = &.{};
        const local_kex = KexInit{
            .cookie = cookie,
            .kex_algorithms = &kex_algorithms,
            .server_host_key_algorithms = &server_host_key_algorithms,
            .encryption_algorithms_client_to_server = &encryption_algorithms,
            .encryption_algorithms_server_to_client = &encryption_algorithms,
            .mac_algorithms_client_to_server = &mac_algorithms,
            .mac_algorithms_server_to_client = &mac_algorithms,
            .compression_algorithms_client_to_server = &compression_algorithms,
            .compression_algorithms_server_to_client = &compression_algorithms,
            .languages_client_to_server = empty,
            .languages_server_to_client = empty,
            .first_kex_packet_follows = false,
            .reserved = 0,
        };
        var icbuf: [2048]u8 = undefined;
        var icw: std.Io.Writer = .fixed(&icbuf);
        try local_kex.encode(&icw);
        const i_c = try gpa.dupe(u8, icw.buffered());
        defer gpa.free(i_c);

        var none_r: CipherState = .none;
        var none_w: CipherState = .none;

        try writePacket(t.writer, &none_w, i_c); // client KEXINIT (seq 0)

        const spkt = try readPacket(t.reader, &none_r, scratch); // server KEXINIT (seq 0)
        if (msgType(spkt) != @intFromEnum(messages.MessageType.SSH_MSG_KEXINIT)) return error.ProtocolError;
        const i_s = try gpa.dupe(u8, spkt.payload);
        defer gpa.free(i_s);

        var sreader: std.Io.Reader = .fixed(spkt.payload[1..]);
        var server_kex = try KexInit.decode(gpa, &sreader);
        defer server_kex.deinit(gpa);

        const neg = try negotiate(server_kex);
        // NB: a server that sets first_kex_packet_follows with a wrong guess is
        // not handled here (real OpenSSH never guesses); part 1 assumes none.

        // KEX (sends KEXDH_INIT seq 1, reads KEXDH_REPLY seq 1). `negotiate`
        // only ever returns a name from `kex_algorithms`; every one of those
        // dispatches to a working implementation here.
        var kex_result = if (isMlkemKex(neg.kex))
            try mlkem768x25519Kex(t.reader, t.writer, &none_w, i_c, i_s, v_c, v_s, verify_host_key)
        else if (isCurve25519Kex(neg.kex))
            try curve25519Kex(t.reader, t.writer, &none_w, i_c, i_s, v_c, v_s, verify_host_key)
        else
            try dhGroupKex(t.reader, t.writer, &none_w, i_c, i_s, v_c, v_s, verify_host_key, neg.kex);
        defer kex_result.zeroize();

        if (t.session_id == null) t.session_id = SessionId.from(kex_result.hash());
        const sid = t.session_id.?.slice();

        // NEWKEYS both ways (still plaintext: seq 2 each direction).
        try writePacket(t.writer, &none_w, &[_]u8{@intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS)});
        const nk = try readPacket(t.reader, &none_r, scratch);
        if (msgType(nk) != @intFromEnum(messages.MessageType.SSH_MSG_NEWKEYS)) return error.ProtocolError;

        // Ciphers take over at seq 3 (KEXINIT=0, KEXDH=1, NEWKEYS=2).
        const start_seq: u32 = 3;
        t.write_cipher = try buildCipher(neg.cipher_c2s, .c2s, kex_result, sid, start_seq);
        t.read_cipher = try buildCipher(neg.cipher_s2c, .s2c, kex_result, sid, start_seq);
    }

    /// Send an already-serialized SSH_MSG_* payload as one binary packet
    /// through `write_cipher`.
    pub fn sendPacket(t: *Transport, payload: []const u8) TransportError!void {
        return writePacket(t.writer, &t.write_cipher, payload);
    }

    /// Receive one binary packet through `read_cipher` into `buf`.
    pub fn recvPacket(t: *Transport, buf: []u8) TransportError!Packet {
        return readPacket(t.reader, &t.read_cipher, buf);
    }

    /// Send SSH_MSG_SERVICE_REQUEST for `service` and wait for the matching
    /// SSH_MSG_SERVICE_ACCEPT (skipping SSH_MSG_IGNORE/DEBUG). Proves the
    /// encrypted channel end-to-end.
    pub fn requestService(t: *Transport, service: []const u8, buf: []u8) TransportError!void {
        var sbuf: [256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&sbuf);
        try w.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_SERVICE_REQUEST));
        try messages.writeString(&w, service);
        try t.sendPacket(w.buffered());
        while (true) {
            const pkt = try t.recvPacket(buf);
            switch (@as(messages.MessageType, @enumFromInt(msgType(pkt)))) {
                .SSH_MSG_IGNORE, .SSH_MSG_DEBUG => continue,
                .SSH_MSG_SERVICE_ACCEPT => return,
                else => return error.ProtocolError,
            }
        }
    }
};

/// Convenience: `Transport.init` followed by `.clientHandshake`.
pub fn connect(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    gpa: std.mem.Allocator,
    verify_host_key: HostKeyVerifier,
) TransportError!Transport {
    var t = Transport.init(reader, writer);
    try t.clientHandshake(gpa, verify_host_key);
    return t;
}

// ── tests ──────────────────────────────────────────────────────────────────

test "algorithm name-lists are non-empty" {
    const t = std.testing;
    try t.expect(kex_algorithms.len > 0);
    try t.expect(server_host_key_algorithms.len > 0);
    try t.expect(encryption_algorithms.len > 0);
    try t.expect(mac_algorithms.len > 0);
    try t.expect(compression_algorithms.len > 0);
}

test "CipherState/Packet/Transport are constructible" {
    const t = std.testing;
    var cipher: CipherState = .none;
    try t.expectEqual(CipherState.none, cipher);
    var in_buf: [1]u8 = .{0};
    var out_buf: [1]u8 = undefined;
    var r: std.Io.Reader = .fixed(&in_buf);
    var w: std.Io.Writer = .fixed(&out_buf);
    var transport_val = Transport.init(&r, &w);
    try t.expect(transport_val.session_id == null);
    _ = &cipher;
    _ = &transport_val;
}

test "KEXINIT encode/decode round-trip" {
    const t = std.testing;
    var cookie: [16]u8 = undefined;
    for (&cookie, 0..) |*c, i| c.* = @intCast(i);
    const empty: []const []const u8 = &.{};
    const src = KexInit{
        .cookie = cookie,
        .kex_algorithms = &kex_algorithms,
        .server_host_key_algorithms = &server_host_key_algorithms,
        .encryption_algorithms_client_to_server = &encryption_algorithms,
        .encryption_algorithms_server_to_client = &encryption_algorithms,
        .mac_algorithms_client_to_server = &mac_algorithms,
        .mac_algorithms_server_to_client = &mac_algorithms,
        .compression_algorithms_client_to_server = &compression_algorithms,
        .compression_algorithms_server_to_client = &compression_algorithms,
        .languages_client_to_server = empty,
        .languages_server_to_client = empty,
        .first_kex_packet_follows = false,
        .reserved = 0,
    };
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try src.encode(&w);
    const payload = w.buffered();
    try t.expectEqual(@intFromEnum(messages.MessageType.SSH_MSG_KEXINIT), payload[0]);

    var r: std.Io.Reader = .fixed(payload[1..]);
    var got = try KexInit.decode(t.allocator, &r);
    defer got.deinit(t.allocator);
    try t.expectEqualSlices(u8, &cookie, &got.cookie);
    try t.expectEqualStrings("mlkem768x25519-sha256", got.kex_algorithms[0]);
    try t.expectEqualStrings("chacha20-poly1305@openssh.com", got.encryption_algorithms_client_to_server[0]);
    try t.expectEqual(@as(usize, 0), got.languages_client_to_server.len);
    try t.expectEqual(false, got.first_kex_packet_follows);
}

test "negotiation picks first client algorithm the server also lists" {
    const client = [_][]const u8{ "a", "b", "c" };
    const server = [_][]const u8{ "x", "c", "b" };
    try std.testing.expectEqualStrings("b", pickFirst(&client, &server).?);
    const none_server = [_][]const u8{"z"};
    try std.testing.expect(pickFirst(&client, &none_server) == null);
}

test "packet codec round-trip: none" {
    const t = std.testing;
    var out: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var wc: CipherState = .none;
    const payload = "hello ssh binary packet protocol";
    try writePacket(&w, &wc, payload);

    var r: std.Io.Reader = .fixed(w.buffered());
    var rc: CipherState = .none;
    var rbuf: [512]u8 = undefined;
    const pkt = try readPacket(&r, &rc, &rbuf);
    try t.expectEqualStrings(payload, pkt.payload);
    // §6: block-aligned, padding >= 4.
    try t.expect(pkt.padding_length >= 4);
    try t.expectEqual(@as(usize, 0), (4 + pkt.packet_length) % 8);
}

test "packet codec round-trip: chacha20-poly1305@openssh (fixed keys)" {
    const t = std.testing;
    var km: [32]u8 = undefined;
    var kh: [32]u8 = undefined;
    for (&km, 0..) |*b, i| b.* = @intCast(i);
    for (&kh, 0..) |*b, i| b.* = @intCast(i + 100);

    var wc: CipherState = .{ .chacha20_poly1305 = .{ .key_main = km, .key_header = kh, .sequence_number = 7 } };
    var rc: CipherState = .{ .chacha20_poly1305 = .{ .key_main = km, .key_header = kh, .sequence_number = 7 } };

    var out: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const payload = "chacha20-poly1305 packet";
    try writePacket(&w, &wc, payload);
    const wire = w.buffered();
    // The 4-byte length field must be encrypted (not the plaintext length).
    try t.expect(std.mem.readInt(u32, wire[0..4], .big) != @as(u32, payload.len + 1));

    var r: std.Io.Reader = .fixed(wire);
    var rbuf: [512]u8 = undefined;
    const pkt = try readPacket(&r, &rc, &rbuf);
    try t.expectEqualStrings(payload, pkt.payload);
    try t.expectEqual(@as(u32, 8), wc.chacha20_poly1305.sequence_number);
    try t.expectEqual(@as(u32, 8), rc.chacha20_poly1305.sequence_number);
}

test "chacha20-poly1305@openssh detects tampering" {
    const t = std.testing;
    const km = [_]u8{3} ** 32;
    const kh = [_]u8{9} ** 32;
    var wc: CipherState = .{ .chacha20_poly1305 = .{ .key_main = km, .key_header = kh, .sequence_number = 0 } };
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writePacket(&w, &wc, "authenticated");
    const wire = w.buffered();
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..wire.len], wire);
    tampered[10] ^= 0x01; // flip a ciphertext byte

    var rc: CipherState = .{ .chacha20_poly1305 = .{ .key_main = km, .key_header = kh, .sequence_number = 0 } };
    var r: std.Io.Reader = .fixed(tampered[0..wire.len]);
    var rbuf: [256]u8 = undefined;
    try t.expectError(error.MacVerificationFailed, readPacket(&r, &rc, &rbuf));
}

test "packet codec round-trip: aes256-ctr + hmac-sha2-256 (fixed keys, multi-packet)" {
    const t = std.testing;
    const ek = [_]u8{5} ** 32;
    const iv = [_]u8{1} ** 16;
    const mk = [_]u8{7} ** 32;
    var wc: CipherState = .{ .aes256_ctr_hmac_sha256 = .{ .enc_key = ek, .enc_iv = iv, .mac_key = mk, .sequence_number = 3 } };
    var rc: CipherState = .{ .aes256_ctr_hmac_sha256 = .{ .enc_key = ek, .enc_iv = iv, .mac_key = mk, .sequence_number = 3 } };

    var out: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    // Two packets exercise the running CTR counter across packet boundaries.
    try writePacket(&w, &wc, "first aes packet payload");
    try writePacket(&w, &wc, "second aes packet, different length!!");

    var r: std.Io.Reader = .fixed(w.buffered());
    var rbuf: [512]u8 = undefined;
    const p1 = try readPacket(&r, &rc, &rbuf);
    try t.expectEqualStrings("first aes packet payload", p1.payload);
    var rbuf2: [512]u8 = undefined;
    const p2 = try readPacket(&r, &rc, &rbuf2);
    try t.expectEqualStrings("second aes packet, different length!!", p2.payload);
    try t.expectEqual(wc.aes256_ctr_hmac_sha256.enc_iv, rc.aes256_ctr_hmac_sha256.enc_iv);
}

test "aes256-ctr detects MAC tampering" {
    const t = std.testing;
    const ek = [_]u8{5} ** 32;
    const iv = [_]u8{2} ** 16;
    const mk = [_]u8{7} ** 32;
    var wc: CipherState = .{ .aes256_ctr_hmac_sha256 = .{ .enc_key = ek, .enc_iv = iv, .mac_key = mk, .sequence_number = 0 } };
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writePacket(&w, &wc, "aes integrity");
    const wire = w.buffered();
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..wire.len], wire);
    tampered[wire.len - 1] ^= 0x80; // flip a MAC byte

    var rc: CipherState = .{ .aes256_ctr_hmac_sha256 = .{ .enc_key = ek, .enc_iv = iv, .mac_key = mk, .sequence_number = 0 } };
    var r: std.Io.Reader = .fixed(tampered[0..wire.len]);
    var rbuf: [256]u8 = undefined;
    try t.expectError(error.MacVerificationFailed, readPacket(&r, &rc, &rbuf));
}

test "RFC 3526 primes: exact bit lengths + canonical RFC bytes" {
    const t = std.testing;
    // group14 = exactly 2048 bits (256 bytes); group16 = exactly 4096 bits
    // (512 bytes). Top bit set (no shorter) + full byte length (no longer).
    try t.expectEqual(@as(usize, 256), group14_prime.len);
    try t.expectEqual(@as(usize, 512), group16_prime.len);
    try t.expect(group14_prime[0] & 0x80 != 0);
    try t.expect(group16_prime[0] & 0x80 != 0);
    // RFC 3526 §3/§5: both primes' top 64 bits and bottom 64 bits are all 1s.
    try t.expectEqualSlices(u8, &[_]u8{0xFF} ** 8, group14_prime[0..8]);
    try t.expectEqualSlices(u8, &[_]u8{0xFF} ** 8, group14_prime[248..256]);
    try t.expectEqualSlices(u8, &[_]u8{0xFF} ** 8, group16_prime[0..8]);
    try t.expectEqualSlices(u8, &[_]u8{0xFF} ** 8, group16_prime[504..512]);
    // The RFC 3526 second 64-bit word is C90FDAA2 2168C234 for every group.
    const w2 = [_]u8{ 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34 };
    try t.expectEqualSlices(u8, &w2, group14_prime[8..16]);
    try t.expectEqualSlices(u8, &w2, group16_prime[8..16]);
}

test "DhGroup.rejectsDegeneratePeerValue: RFC 4253 §8 upper bound (F1 regression)" {
    const t = std.testing;
    inline for (.{ "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512" }) |name| {
        const group = DhGroup.forName(name).?;
        // Degenerate: v == p forces K = 0; v == p-1 forces K in {1, p-1}.
        // Both MUST now be rejected — this is exactly the audit's F1 gap
        // ("comment promises 1 < v < p-1 but only the lower bound was
        // enforced").
        try t.expect(group.rejectsDegeneratePeerValue(group.prime));
        try t.expect(group.rejectsDegeneratePeerValue(group.prime_minus_1));
        // Oversized (longer than p) is still rejected (pre-existing check,
        // must not have regressed).
        var oversized: [group16_prime.len + 1]u8 = undefined;
        @memset(&oversized, 0xAB);
        try t.expect(group.rejectsDegeneratePeerValue(oversized[0 .. group.prime.len + 1]));
        // The classic 0/1 lower-bound rejects, unchanged.
        try t.expect(group.rejectsDegeneratePeerValue(&.{}));
        try t.expect(group.rejectsDegeneratePeerValue(&.{0}));
        try t.expect(group.rejectsDegeneratePeerValue(&.{1}));
        // A genuine, well-inside-the-range value (p-2) must still be
        // ACCEPTED — the fix must not have overreached into rejecting
        // legitimate peer values.
        var p_minus_2_buf: [group16_prime.len]u8 = undefined;
        const pm1_len = group.prime_minus_1.len;
        @memcpy(p_minus_2_buf[0..pm1_len], group.prime_minus_1);
        p_minus_2_buf[pm1_len - 1] -= 1;
        try t.expect(!group.rejectsDegeneratePeerValue(p_minus_2_buf[0..pm1_len]));
        // And a small, unambiguously-legitimate value (g = 2) is accepted.
        try t.expect(!group.rejectsDegeneratePeerValue(&.{2}));
    }
}

/// A `HostKeyVerifier` never actually reached by the KEX-level replay tests
/// below (the degenerate-`f` check fails before host-key verification is
/// ever consulted) — present only to satisfy `dhGroupKex`'s signature.
fn unreachableHostKeyVerifier(key_type: []const u8, key_blob: []const u8) bool {
    _ = key_type;
    _ = key_blob;
    unreachable;
}

/// Builds a raw (unencrypted, `.none` cipher) `SSH_MSG_KEXDH_REPLY` packet
/// carrying `f_mag` as the peer's DH public value, written into `out`.
/// `K_S`/`sig` are throwaway bytes — `dhGroupKex` must reject `f_mag`
/// before it ever parses them as a real host key or signature.
fn fakeKexdhReply(f_mag: []const u8, out: []u8) ![]const u8 {
    var payload_buf: [group16_prime.len + 64]u8 = undefined;
    var pw: std.Io.Writer = .fixed(&payload_buf);
    try pw.writeByte(@intFromEnum(messages.MessageType.SSH_MSG_KEXDH_REPLY));
    try messages.writeString(&pw, "not-a-real-host-key-blob");
    try messages.writeMpint(&pw, f_mag);
    try messages.writeString(&pw, "not-a-real-signature");

    var none: CipherState = .none;
    var w: std.Io.Writer = .fixed(out);
    try writePacket(&w, &none, pw.buffered());
    return w.buffered();
}

test "dhGroupKex (client): rejects a KEXDH_REPLY carrying f == p or f == p-1" {
    const kex_name = "diffie-hellman-group14-sha256";
    const group = DhGroup.forName(kex_name).?;

    for ([_][]const u8{ group.prime, group.prime_minus_1 }) |degenerate_f| {
        var reply_buf: [1024]u8 = undefined;
        const reply = try fakeKexdhReply(degenerate_f, &reply_buf);

        var r: std.Io.Reader = .fixed(reply);
        var out_scratch: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out_scratch);
        var none: CipherState = .none;

        try std.testing.expectError(
            error.KexFailed,
            dhGroupKex(&r, &w, &none, "I_C", "I_S", "V_C", "V_S", unreachableHostKeyVerifier, kex_name),
        );
    }
}

test "packet codec round-trip: aes256-gcm@openssh (counter increments per packet)" {
    const t = std.testing;
    const key = [_]u8{0x11} ** 32;
    const fixed_iv = [_]u8{ 0x22, 0x33, 0x44, 0x55 };
    var wc: CipherState = .{ .aes_gcm = .{ .key = key, .key_bits = .aes256, .fixed_iv = fixed_iv, .invocation_counter = 5, .sequence_number = 3 } };
    var rc: CipherState = .{ .aes_gcm = .{ .key = key, .key_bits = .aes256, .fixed_iv = fixed_iv, .invocation_counter = 5, .sequence_number = 3 } };

    var out: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    // Two packets: the 8-byte invocation counter must advance by 1 each,
    // independent of the SSH sequence number.
    try writePacket(&w, &wc, "first gcm packet");
    try writePacket(&w, &wc, "second gcm packet, different length!!");
    try t.expectEqual(@as(u64, 7), wc.aes_gcm.invocation_counter);
    const wire = w.buffered();
    // The 4-byte length field is AAD, NOT encrypted: it equals pkt_len (a
    // multiple of 16 under the RFC 5647 block-alignment).
    const pkt_len0 = std.mem.readInt(u32, wire[0..4], .big);
    try t.expectEqual(@as(u32, 0), pkt_len0 % 16);

    var r: std.Io.Reader = .fixed(wire);
    var rbuf: [512]u8 = undefined;
    const p1 = try readPacket(&r, &rc, &rbuf);
    try t.expectEqualStrings("first gcm packet", p1.payload);
    var rbuf2: [512]u8 = undefined;
    const p2 = try readPacket(&r, &rc, &rbuf2);
    try t.expectEqualStrings("second gcm packet, different length!!", p2.payload);
    try t.expectEqual(@as(u64, 7), rc.aes_gcm.invocation_counter);
}

test "packet codec round-trip: aes128-gcm@openssh + GCM tag detects tampering" {
    const t = std.testing;
    var key = [_]u8{0} ** 32;
    for (key[0..16], 0..) |*b, i| b.* = @intCast(i + 1);
    const fixed_iv = [_]u8{ 1, 2, 3, 4 };
    var wc: CipherState = .{ .aes_gcm = .{ .key = key, .key_bits = .aes128, .fixed_iv = fixed_iv, .invocation_counter = 0, .sequence_number = 0 } };
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writePacket(&w, &wc, "aes128-gcm authenticated payload");
    const wire = w.buffered();

    var rc: CipherState = .{ .aes_gcm = .{ .key = key, .key_bits = .aes128, .fixed_iv = fixed_iv, .invocation_counter = 0, .sequence_number = 0 } };
    var r: std.Io.Reader = .fixed(wire);
    var rbuf: [256]u8 = undefined;
    const p = try readPacket(&r, &rc, &rbuf);
    try t.expectEqualStrings("aes128-gcm authenticated payload", p.payload);

    // Flip a ciphertext byte -> GCM tag must reject.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..wire.len], wire);
    tampered[8] ^= 0x01;
    var rc2: CipherState = .{ .aes_gcm = .{ .key = key, .key_bits = .aes128, .fixed_iv = fixed_iv, .invocation_counter = 0, .sequence_number = 0 } };
    var r2: std.Io.Reader = .fixed(tampered[0..wire.len]);
    var rbuf2: [256]u8 = undefined;
    try t.expectError(error.MacVerificationFailed, readPacket(&r2, &rc2, &rbuf2));
}

test "ML-KEM-768 raw encaps/decaps round-trip + wire lengths" {
    const t = std.testing;
    try t.expectEqual(@as(usize, 1184), mlkem_pk_len);
    try t.expectEqual(@as(usize, 1088), mlkem_ct_len);
    var seed: [MLKem768.seed_length]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = try MLKem768.KeyPair.generateDeterministic(seed);
    var es: [MLKem768.encaps_seed_length]u8 = undefined;
    for (&es, 0..) |*b, i| b.* = @intCast(i + 7);
    const enc = kp.public_key.encapsDeterministic(&es);
    const dec = try kp.secret_key.decaps(&enc.ciphertext);
    try t.expectEqualSlices(u8, &enc.shared_secret, &dec);
}

test "KDF is deterministic and matches the RFC 4253 §7.2 formula for one block" {
    const t = std.testing;
    const ss = [_]u8{0x42} ** 32; // high bit clear -> mpint has no sign pad
    const h = [_]u8{0x11} ** 32;
    const sid = [_]u8{0x22} ** 32;

    const a = deriveKeys(ss, h, sid);
    const b = deriveKeys(ss, h, sid);
    try t.expectEqualSlices(u8, &a.enc_key_client_to_server, &b.enc_key_client_to_server);
    // Different letters must produce different key material.
    try t.expect(!std.mem.eql(u8, &a.enc_key_client_to_server, &a.enc_key_server_to_client));

    // Recompute K1 for letter 'A' by hand: HASH(mpint(K) || H || 'A' || sid).
    var kmbuf: [4 + 33]u8 = undefined;
    const k_mpint = encodeMpint(&kmbuf, &ss);
    var sh = Sha256.init(.{});
    sh.update(k_mpint);
    sh.update(&h);
    sh.update(&[_]u8{'A'});
    sh.update(&sid);
    var expect: [32]u8 = undefined;
    sh.final(&expect);
    try t.expectEqualSlices(u8, expect[0..16], &a.iv_client_to_server);
}

test "host-key parse + signature verify: ed25519 (generated key)" {
    const t = std.testing;
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i + 1);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pk_bytes = kp.public_key.toBytes();

    // Build K_S = string "ssh-ed25519" || string pubkey(32).
    var ksbuf: [128]u8 = undefined;
    var ksw: std.Io.Writer = .fixed(&ksbuf);
    try messages.writeString(&ksw, "ssh-ed25519");
    try messages.writeString(&ksw, &pk_bytes);
    const k_s = ksw.buffered();

    const h = [_]u8{0xAB} ** 32;
    const signature = try kp.sign(&h, null);
    const sig_raw = signature.toBytes();

    // Build sig_blob = string "ssh-ed25519" || string sig(64).
    var sbuf: [128]u8 = undefined;
    var sw: std.Io.Writer = .fixed(&sbuf);
    try messages.writeString(&sw, "ssh-ed25519");
    try messages.writeString(&sw, &sig_raw);
    const sig_blob = sw.buffered();

    try verifySignature("ssh-ed25519", k_s, sig_blob, &h);
    // A different message must fail.
    const h2 = [_]u8{0xCD} ** 32;
    try t.expectError(error.HostKeyVerificationFailed, verifySignature("ssh-ed25519", k_s, sig_blob, &h2));
}

// ── live interop test against a real OpenSSH sshd (gated) ───────────────────

const HostKeyCapture = struct {
    var expected_ed25519: [32]u8 = undefined;
    var matched: bool = false;

    fn verify(key_type: []const u8, key_blob: []const u8) bool {
        matched = false;
        if (!std.mem.eql(u8, key_type, "ssh-ed25519")) return false;
        var sr = SliceReader{ .b = key_blob };
        _ = (sr.string() catch return false); // type
        const pk = sr.string() catch return false;
        if (pk.len != 32) return false;
        if (std.mem.eql(u8, pk, &expected_ed25519)) {
            matched = true;
            return true;
        }
        return false;
    }
};

fn readEd25519PubFromKeyFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![32]u8 {
    // OpenSSH ".pub" line: "ssh-ed25519 <base64 blob> comment".
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4096));
    defer gpa.free(data);
    var it = std.mem.tokenizeScalar(u8, data, ' ');
    _ = it.next() orelse return error.BadKey; // "ssh-ed25519"
    const b64 = it.next() orelse return error.BadKey;
    var blob: [128]u8 = undefined;
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    if (n > blob.len) return error.BadKey;
    try dec.decode(blob[0..n], b64);
    var sr = SliceReader{ .b = blob[0..n] };
    _ = try sr.string(); // "ssh-ed25519"
    const pk = try sr.string();
    if (pk.len != 32) return error.BadKey;
    var out: [32]u8 = undefined;
    @memcpy(&out, pk);
    return out;
}

fn liveInterop(kex_name: []const u8, cipher_name: []const u8) !void {
    const gpa = std.testing.allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const cwd = std.Io.Dir.cwd();

    // Locate a runnable sshd, else skip.
    const sshd_path = "/usr/sbin/sshd";
    cwd.access(io, sshd_path, .{}) catch return error.SkipZigTest;

    // Throwaway temp dir at a known absolute path (openat ignores the dirfd
    // for absolute sub-paths, so this yields a usable absolute path string).
    var rnd: [8]u8 = undefined;
    fillRandom(&rnd);
    const hex = std.fmt.bytesToHex(&rnd, .lower);
    const dir_path = try std.fmt.allocPrint(gpa, "/tmp/zig_ssh_test_{s}", .{&hex});
    defer gpa.free(dir_path);
    var work = cwd.createDirPathOpen(io, dir_path, .{}) catch return error.SkipZigTest;
    defer {
        work.close(io);
        cwd.deleteTree(io, dir_path) catch {};
    }

    const hk_path = try std.fmt.allocPrint(gpa, "{s}/hk", .{dir_path});
    defer gpa.free(hk_path);

    // Generate an ephemeral ed25519 host key.
    {
        var child = std.process.spawn(io, .{
            .argv = &.{ "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hk_path },
            .stdout = .ignore,
            .stderr = .ignore,
        }) catch return error.SkipZigTest;
        const term = child.wait(io) catch return error.SkipZigTest;
        switch (term) {
            .exited => |c| if (c != 0) return error.SkipZigTest,
            else => return error.SkipZigTest,
        }
    }

    const pub_path = try std.fmt.allocPrint(gpa, "{s}.pub", .{hk_path});
    defer gpa.free(pub_path);
    HostKeyCapture.expected_ed25519 = readEd25519PubFromKeyFile(gpa, io, pub_path) catch return error.SkipZigTest;

    // Pick a loopback port.
    var portbuf: [2]u8 = undefined;
    fillRandom(&portbuf);
    const port: u16 = 20000 + (std.mem.readInt(u16, &portbuf, .big) % 20000);
    const port_opt = try std.fmt.allocPrint(gpa, "Port={d}", .{port});
    defer gpa.free(port_opt);
    const ciphers_opt = try std.fmt.allocPrint(gpa, "Ciphers={s}", .{cipher_name});
    defer gpa.free(ciphers_opt);
    const kex_opt = try std.fmt.allocPrint(gpa, "KexAlgorithms={s}", .{kex_name});
    defer gpa.free(kex_opt);

    // Start sshd (foreground master; all config via -o, no config file).
    var sshd = std.process.spawn(io, .{
        .argv = &.{
            sshd_path,            "-D", "-e",                      "-f",
            "/dev/null",          "-h", hk_path,                   "-o",
            port_opt,             "-o", "ListenAddress=127.0.0.1", "-o",
            "UsePAM=no",          "-o", "StrictModes=no",          "-o",
            "PidFile=none",       "-o", "LogLevel=QUIET",          "-o",
            kex_opt,              "-o", ciphers_opt,               "-o",
            "MACs=hmac-sha2-256",
        },
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SkipZigTest;
    defer sshd.kill(io); // idempotent + reaps; safe even if never connected

    // Connect (retry until sshd is listening, ~3s budget).
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var stream: std.Io.net.Stream = blk: {
        var tries: usize = 0;
        while (tries < 60) : (tries += 1) {
            if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
            var ts = std.os.linux.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
            _ = std.os.linux.nanosleep(&ts, null);
        }
        // sshd never came up (e.g. cannot run as non-root here): skip loudly.
        return error.SkipZigTest;
    };
    defer stream.close(io);

    var rbuf: [32 * 1024]u8 = undefined;
    var wbuf: [32 * 1024]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    var transport = Transport.init(&sr.interface, &sw.interface);
    try transport.clientHandshake(gpa, HostKeyCapture.verify);
    try std.testing.expect(HostKeyCapture.matched);

    // The real end-to-end proof: an encrypted SERVICE_REQUEST that decrypts
    // to a SERVICE_ACCEPT under the negotiated cipher + MAC.
    var pbuf: [8192]u8 = undefined;
    try transport.requestService("ssh-userauth", &pbuf);

    // Confirm the cipher we forced is what got installed.
    switch (transport.read_cipher) {
        .chacha20_poly1305 => try std.testing.expect(std.mem.eql(u8, cipher_name, "chacha20-poly1305@openssh.com")),
        .aes256_ctr_hmac_sha256 => try std.testing.expect(std.mem.eql(u8, cipher_name, "aes256-ctr")),
        .aes_gcm => |st| switch (st.key_bits) {
            .aes256 => try std.testing.expectEqualStrings("aes256-gcm@openssh.com", cipher_name),
            .aes128 => try std.testing.expectEqualStrings("aes128-gcm@openssh.com", cipher_name),
        },
        .none => return error.ProtocolError,
    }
}

test "live interop against OpenSSH sshd — curve25519 + chacha20-poly1305@openssh.com" {
    try liveInterop("curve25519-sha256", "chacha20-poly1305@openssh.com");
}

test "live interop against OpenSSH sshd — curve25519 + aes256-ctr" {
    try liveInterop("curve25519-sha256", "aes256-ctr");
}

test "live interop against OpenSSH sshd — diffie-hellman-group14-sha256" {
    try liveInterop("diffie-hellman-group14-sha256", "aes256-ctr");
}

test "live interop against OpenSSH sshd — diffie-hellman-group16-sha512" {
    try liveInterop("diffie-hellman-group16-sha512", "aes256-ctr");
}

test "live interop against OpenSSH sshd — mlkem768x25519-sha256" {
    try liveInterop("mlkem768x25519-sha256", "chacha20-poly1305@openssh.com");
}

test "live interop against OpenSSH sshd — aes256-gcm@openssh.com" {
    try liveInterop("curve25519-sha256", "aes256-gcm@openssh.com");
}

test "live interop against OpenSSH sshd — aes128-gcm@openssh.com" {
    try liveInterop("curve25519-sha256", "aes128-gcm@openssh.com");
}
