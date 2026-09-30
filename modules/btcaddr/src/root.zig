// SPDX-License-Identifier: MIT
//! btcaddr -- the Bitcoin address layer above the `bech32` codec:
//! scriptPubKey <-> address string for P2PKH, P2SH, P2WPKH, P2WSH, P2TR and
//! every future witness version (v1..v16, BIP350), network detection from the
//! version byte / HRP, WIF private-key encode/decode, and the P2SH / P2WSH /
//! P2SH-P2WPKH script helpers.
//!
//! What it does NOT do: parse or interpret Script (a scriptPubKey is matched
//! against seven fixed byte templates, nothing else), derive keys, tweak a
//! taproot key, or check that a pubkey is a point on the curve. An unrecognised
//! script is `error.UnsupportedScript`, never a guessed address.
//!
//! Networks. Bitcoin's networks do not have distinct encodings, and this module
//! says so rather than pick one: testnet, signet and regtest all use the base58
//! version bytes 0x6f / 0xc4 / 0xef; testnet and signet share the `tb` HRP;
//! only mainnet (`bc`, 0x00/0x05/0x80) and regtest segwit (`bcrt`) are
//! unambiguous. A decoded string therefore reports a `Chains` SET -- the
//! networks the string is valid on -- and `toScriptPubKeyFor` checks one
//! network explicitly. Encoding takes a concrete `Network`.
//!
//! No allocation. Untrusted input: `toScriptPubKey` and `wifDecode` are
//! fail-closed with a typed error per rejection reason. A WIF key is secret
//! material: every scratch buffer that holds it is wiped, and `Wif.wipe` /
//! the caller-side buffer of `wifEncode` are the caller's to clear.
//!
//! Provenance: original work of the zig-libs authors (MIT), from BIP13/16
//! (P2SH), BIP141/143 (segwit), BIP173/350 (bech32/bech32m) and the WIF
//! description on the Bitcoin wiki. Verified against Bitcoin Core's
//! `key_io_valid.json` / `key_io_invalid.json` (MIT test data, see `NOTICE`);
//! no third-party source was read or ported.

const std = @import("std");
const bech32 = @import("bech32");
const ripemd160 = @import("ripemd160");

const base58 = bech32.base58;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const meta = .{
    // The module catalog's one-line entry (README table is rendered from it).
    .doc = "Bitcoin address layer -- scriptPubKey <-> address (P2PKH/P2SH/P2WPKH/P2WSH/P2TR/witness v1-16), network detection, WIF keys, P2SH/P2WSH helpers.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant, // pure functions over caller-owned buffers; no shared state
    .model_after = "Bitcoin Core key_io.cpp (DecodeDestination / EncodeSecret) + rust-bitcoin Address",
    .deps = .{ "bech32", "ripemd160" }, // codec + hash160; SHA-256 from std
};

// -- networks -------------------------------------------------------------

/// A concrete network, for ENCODING. Decoding cannot always tell testnet,
/// signet and regtest apart -- see `Chains`.
pub const Network = enum {
    mainnet,
    testnet,
    signet,
    regtest,

    /// Base58Check version byte of a P2PKH address.
    pub fn p2pkhVersion(self: Network) u8 {
        return if (self == .mainnet) 0x00 else 0x6f;
    }
    /// Base58Check version byte of a P2SH address.
    pub fn p2shVersion(self: Network) u8 {
        return if (self == .mainnet) 0x05 else 0xc4;
    }
    /// Base58Check version byte of a WIF private key.
    pub fn wifVersion(self: Network) u8 {
        return if (self == .mainnet) 0x80 else 0xef;
    }
    /// Segwit human-readable part. `testnet` and `signet` share `tb`.
    pub fn hrp(self: Network) []const u8 {
        return switch (self) {
            .mainnet => "bc",
            .testnet, .signet => "tb",
            .regtest => "bcrt",
        };
    }
};

/// The set of networks a decoded string is valid on. `.{ .mainnet = true }`
/// is the only single-network base58 result; every base58 test-network string
/// is valid on testnet, signet AND regtest, and a `tb` address on testnet and
/// signet.
pub const Chains = packed struct(u4) {
    mainnet: bool = false,
    testnet: bool = false,
    signet: bool = false,
    regtest: bool = false,

    pub fn contains(self: Chains, n: Network) bool {
        return switch (n) {
            .mainnet => self.mainnet,
            .testnet => self.testnet,
            .signet => self.signet,
            .regtest => self.regtest,
        };
    }

    /// How many networks the string is valid on (always >= 1 for a decoded value).
    pub fn count(self: Chains) u3 {
        return @as(u3, @intFromBool(self.mainnet)) + @intFromBool(self.testnet) +
            @intFromBool(self.signet) + @intFromBool(self.regtest);
    }

    /// The network, when the string pins exactly one; null when ambiguous.
    pub fn unique(self: Chains) ?Network {
        if (self.count() != 1) return null;
        if (self.mainnet) return .mainnet;
        if (self.testnet) return .testnet;
        if (self.signet) return .signet;
        return .regtest;
    }
};

const chains_main: Chains = .{ .mainnet = true };
const chains_base58_test: Chains = .{ .testnet = true, .signet = true, .regtest = true };
const chains_tb: Chains = .{ .testnet = true, .signet = true };
const chains_bcrt: Chains = .{ .regtest = true };

// -- scripts --------------------------------------------------------------

/// The standard output types this module converts. Anything else is not an
/// address (bare multisig, P2PK, OP_RETURN, non-standard scripts).
pub const ScriptKind = enum {
    p2pkh,
    p2sh,
    p2wpkh,
    p2wsh,
    p2tr,
    /// Witness v1 with a program that is not 32 bytes, or v2..v16: encodable
    /// (BIP350) but with no defined spending rules yet.
    witness_unknown,
};

/// Longest scriptPubKey handled: a witness program of 40 bytes + 2 header bytes.
pub const max_script_len = 42;
/// Longest address string produced (bech32's 90-character ceiling).
pub const max_address_len = bech32.max_len;
/// Longest WIF string: 1 + 32 + 1 + 4 bytes in base58.
pub const max_wif_len = 52;

const op_dup = 0x76;
const op_hash160 = 0xa9;
const op_equalverify = 0x88;
const op_equal = 0x87;
const op_checksig = 0xac;

/// Matches `script` against the seven standard templates. Exact match only:
/// no trailing bytes, no non-minimal pushes.
pub fn classify(script: []const u8) ?ScriptKind {
    if (script.len == 25 and script[0] == op_dup and script[1] == op_hash160 and
        script[2] == 0x14 and script[23] == op_equalverify and script[24] == op_checksig)
        return .p2pkh;
    if (script.len == 23 and script[0] == op_hash160 and script[1] == 0x14 and script[22] == op_equal)
        return .p2sh;
    // Witness program: OP_0 / OP_1..OP_16, one direct push of 2..40 bytes.
    if (script.len < 4 or script.len > max_script_len) return null;
    const version: u8 = if (script[0] == 0x00) 0 else if (script[0] >= 0x51 and script[0] <= 0x60) script[0] - 0x50 else return null;
    const plen = script.len - 2;
    if (script[1] != plen) return null;
    if (version == 0) return switch (plen) {
        20 => .p2wpkh,
        32 => .p2wsh,
        else => null, // BIP141: a v0 program is exactly 20 or 32 bytes
    };
    if (version == 1 and plen == 32) return .p2tr;
    return .witness_unknown;
}

pub fn scriptP2pkh(hash: *const [20]u8) [25]u8 {
    var s: [25]u8 = undefined;
    s[0..3].* = .{ op_dup, op_hash160, 0x14 };
    s[3..23].* = hash.*;
    s[23..25].* = .{ op_equalverify, op_checksig };
    return s;
}

pub fn scriptP2sh(hash: *const [20]u8) [23]u8 {
    var s: [23]u8 = undefined;
    s[0..2].* = .{ op_hash160, 0x14 };
    s[2..22].* = hash.*;
    s[22] = op_equal;
    return s;
}

pub fn scriptP2wpkh(hash: *const [20]u8) [22]u8 {
    var s: [22]u8 = undefined;
    s[0..2].* = .{ 0x00, 0x14 };
    s[2..].* = hash.*;
    return s;
}

pub fn scriptP2wsh(hash: *const [32]u8) [34]u8 {
    var s: [34]u8 = undefined;
    s[0..2].* = .{ 0x00, 0x20 };
    s[2..].* = hash.*;
    return s;
}

/// `output_key` is the final (already tweaked) 32-byte x-only key; tweaking is
/// the caller's (taproot module's) job.
pub fn scriptP2tr(output_key: *const [32]u8) [34]u8 {
    var s: [34]u8 = undefined;
    s[0..2].* = .{ 0x51, 0x20 };
    s[2..].* = output_key.*;
    return s;
}

// -- addresses ------------------------------------------------------------

/// An address string in a fixed buffer.
pub const Address = struct {
    buf: [max_address_len]u8,
    len: u8,

    pub fn slice(self: *const Address) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const ScriptError = base58.Error || bech32.EncodeError || bech32.SegwitError || error{
    /// Not one of the seven standard templates (see `classify`), or a witness
    /// program of a length BIP141 does not allow.
    UnsupportedScript,
};

/// scriptPubKey -> address string on `network`.
pub fn fromScriptPubKey(script: []const u8, network: Network) ScriptError!Address {
    const kind = classify(script) orelse return error.UnsupportedScript;
    var out: Address = undefined;
    out.len = 0;
    switch (kind) {
        .p2pkh, .p2sh => {
            var payload: [21]u8 = undefined;
            if (kind == .p2pkh) {
                payload[0] = network.p2pkhVersion();
                payload[1..].* = script[3..23].*;
            } else {
                payload[0] = network.p2shVersion();
                payload[1..].* = script[2..22].*;
            }
            out.len = @intCast((try base58.checkEncode(&payload, &out.buf)).len);
        },
        .p2wpkh, .p2wsh, .p2tr, .witness_unknown => {
            const witver: u5 = if (script[0] == 0x00) 0 else @intCast(script[0] - 0x50);
            const enc = try bech32.encodeSegwit(network.hrp(), witver, script[2..]);
            const s = enc.slice();
            @memcpy(out.buf[0..s.len], s);
            out.len = @intCast(s.len);
        },
    }
    return out;
}

/// A decoded address.
pub const Decoded = struct {
    /// Networks the address is valid on (see `Chains`).
    chains: Chains,
    kind: ScriptKind,
    script_buf: [max_script_len]u8,
    script_len: u8,

    /// The scriptPubKey the address pays to.
    pub fn script(self: *const Decoded) []const u8 {
        return self.script_buf[0..self.script_len];
    }

    /// The hash / witness program inside the script.
    pub fn payload(self: *const Decoded) []const u8 {
        return switch (self.kind) {
            .p2pkh => self.script_buf[3..23],
            .p2sh => self.script_buf[2..22],
            else => self.script_buf[2..self.script_len],
        };
    }
};

pub const AddressError = base58.CheckError || bech32.SegwitError || error{
    /// A valid bech32 string whose HRP is none of `bc`, `tb`, `bcrt`.
    UnknownHrp,
    /// Base58Check payload with a version byte that is no known address version
    /// (a WIF key handed in as an address ends up here).
    UnknownVersionByte,
    /// Base58Check payload that is not 1 + 20 bytes.
    InvalidPayloadLength,
    /// `toScriptPubKeyFor`: valid address, but not on the requested network.
    WrongNetwork,
};

/// Address string -> scriptPubKey, with the set of networks it is valid on.
/// Accepts upper-case bech32 (BIP173) and nothing else non-canonical.
pub fn toScriptPubKey(address: []const u8) AddressError!Decoded {
    if (hasSegwitPrefix(address)) return decodeSegwitAddress(address);
    // A well-formed bech32 string with a foreign HRP is a different failure
    // from a malformed base58 one; say which.
    if (bech32.decode(address)) |_| return error.UnknownHrp else |_| {}
    return decodeBase58Address(address);
}

/// As `toScriptPubKey`, but the address must be valid on `network`.
pub fn toScriptPubKeyFor(address: []const u8, network: Network) AddressError!Decoded {
    const d = try toScriptPubKey(address);
    if (!d.chains.contains(network)) return error.WrongNetwork;
    return d;
}

fn hasSegwitPrefix(s: []const u8) bool {
    return startsWithNoCase(s, "bc1") or startsWithNoCase(s, "tb1") or startsWithNoCase(s, "bcrt1");
}

fn startsWithNoCase(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    for (prefix, s[0..prefix.len]) |p, c| {
        if (p != bech32.toLower(c)) return false;
    }
    return true;
}

fn decodeSegwitAddress(address: []const u8) AddressError!Decoded {
    const d = try bech32.decode(address);
    const hrp = d.hrp();
    const chains: Chains = if (std.mem.eql(u8, hrp, "bc"))
        chains_main
    else if (std.mem.eql(u8, hrp, "tb"))
        chains_tb
    else if (std.mem.eql(u8, hrp, "bcrt"))
        chains_bcrt
    else
        return error.UnknownHrp;

    const seg = try bech32.decodeSegwit(hrp, address);
    const program = seg.program();
    var out: Decoded = undefined;
    out.script_buf[0] = if (seg.witver == 0) 0x00 else 0x50 + @as(u8, seg.witver);
    out.script_buf[1] = @intCast(program.len);
    @memcpy(out.script_buf[2..][0..program.len], program);
    out.script_len = @intCast(2 + program.len);
    out.chains = chains;
    // decodeSegwit enforced the BIP141 lengths, so classify cannot fail.
    out.kind = classify(out.script()) orelse return error.InvalidProgramLength;
    return out;
}

fn decodeBase58Address(address: []const u8) AddressError!Decoded {
    // Wide enough for a WIF payload (33/34 bytes): a private key pasted into an
    // address field is reported as such, and the scratch is wiped either way.
    var buf: [34]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const payload = base58.checkDecode(address, &buf) catch |e| return switch (e) {
        error.BufferTooSmall => error.InvalidPayloadLength,
        else => e,
    };
    if (payload.len != 21) {
        if (payload.len > 0 and (payload[0] == 0x80 or payload[0] == 0xef)) return error.UnknownVersionByte;
        return error.InvalidPayloadLength;
    }
    const hash: *const [20]u8 = payload[1..21];

    var out: Decoded = undefined;
    switch (payload[0]) {
        0x00, 0x6f => {
            out.script_buf[0..25].* = scriptP2pkh(hash);
            out.script_len = 25;
            out.kind = .p2pkh;
        },
        0x05, 0xc4 => {
            out.script_buf[0..23].* = scriptP2sh(hash);
            out.script_len = 23;
            out.kind = .p2sh;
        },
        else => return error.UnknownVersionByte,
    }
    out.chains = if (payload[0] == 0x00 or payload[0] == 0x05) chains_main else chains_base58_test;
    return out;
}

// -- WIF ------------------------------------------------------------------

/// The order of the secp256k1 group; a valid private key is in [1, n-1].
const secp256k1_order = [32]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

fn keyInRange(key: *const [32]u8) bool {
    const zero = [_]u8{0} ** 32;
    if (std.mem.eql(u8, key, &zero)) return false;
    return std.mem.order(u8, key, &secp256k1_order) == .lt;
}

/// A decoded WIF private key. SECRET: call `wipe` when done.
pub const Wif = struct {
    chains: Chains,
    key: [32]u8,
    /// True when the key was flagged for a compressed public key (0x01 suffix).
    compressed: bool,

    pub fn wipe(self: *Wif) void {
        std.crypto.secureZero(u8, &self.key);
    }
};

pub const WifDecodeError = base58.CheckError || error{
    /// Version byte is neither 0x80 (mainnet) nor 0xef (test networks).
    UnknownVersionByte,
    /// Payload is not version + 32 (+ flag) bytes.
    InvalidPayloadLength,
    /// A 34-byte payload whose last byte is not 0x01.
    InvalidCompressionFlag,
    /// The 32-byte scalar is zero or >= the curve order.
    InvalidKey,
};

/// Decodes a WIF string. Fail-closed; scratch is wiped on every exit.
pub fn wifDecode(s: []const u8) WifDecodeError!Wif {
    var buf: [34]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const payload = base58.checkDecode(s, &buf) catch |e| return switch (e) {
        error.BufferTooSmall => error.InvalidPayloadLength,
        else => e,
    };
    if (payload.len != 33 and payload.len != 34) return error.InvalidPayloadLength;
    const chains: Chains = switch (payload[0]) {
        0x80 => chains_main,
        0xef => chains_base58_test,
        else => return error.UnknownVersionByte,
    };
    if (payload.len == 34 and payload[33] != 0x01) return error.InvalidCompressionFlag;
    if (!keyInRange(payload[1..33])) return error.InvalidKey;
    return .{ .chains = chains, .key = payload[1..33].*, .compressed = payload.len == 34 };
}

pub const WifEncodeError = base58.Error || error{InvalidKey};

/// Encodes `key` as WIF for `network` into `out` (>= `max_wif_len` bytes) and
/// returns the written prefix. The output is secret: the caller wipes `out`.
pub fn wifEncode(key: *const [32]u8, compressed: bool, network: Network, out: []u8) WifEncodeError![]const u8 {
    if (!keyInRange(key)) return error.InvalidKey;
    var payload: [34]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload);
    payload[0] = network.wifVersion();
    payload[1..33].* = key.*;
    payload[33] = 0x01;
    return base58.checkEncode(payload[0..if (compressed) 34 else 33], out);
}

// -- helpers: script hash / key hash -> output script ----------------------

pub const HelperError = error{
    /// Public key is not 33 bytes 02/03 or 65 bytes 04. (Curve membership is not checked.)
    InvalidPublicKey,
    /// P2WPKH / P2SH-P2WPKH need a compressed key (BIP141 policy).
    UncompressedPublicKey,
    /// P2SH redeem script longer than 520 bytes (cannot be pushed to spend).
    RedeemScriptTooLarge,
    /// P2WSH witness script longer than 10000 bytes (consensus limit).
    WitnessScriptTooLarge,
};

/// P2SH: a redeem script is one stack element.
pub const max_redeem_script_len = 520;
/// P2WSH: consensus limit on the witness script (BIP141 / MAX_SCRIPT_SIZE).
pub const max_witness_script_len = 10000;

/// `RIPEMD160(SHA256(data))`.
pub fn hash160(data: []const u8) [20]u8 {
    var h: [20]u8 = undefined;
    ripemd160.hash160(data, &h);
    return h;
}

/// `SHA256(data)`.
pub fn sha256(data: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash(data, &h, .{});
    return h;
}

fn isCompressedKey(pk: []const u8) bool {
    return pk.len == 33 and (pk[0] == 0x02 or pk[0] == 0x03);
}

fn checkPublicKey(pk: []const u8) HelperError!void {
    if (isCompressedKey(pk)) return;
    if (pk.len == 65 and pk[0] == 0x04) return;
    return error.InvalidPublicKey;
}

fn checkCompressed(pk: []const u8) HelperError!void {
    try checkPublicKey(pk);
    if (!isCompressedKey(pk)) return error.UncompressedPublicKey;
}

/// P2PKH script of a public key (compressed or uncompressed).
pub fn p2pkhOfPublicKey(pubkey: []const u8) HelperError![25]u8 {
    try checkPublicKey(pubkey);
    return scriptP2pkh(&hash160(pubkey));
}

/// P2WPKH script of a compressed public key. It is also the redeem script of
/// the P2SH-P2WPKH wrapper (BIP141 "P2WPKH nested in BIP16 P2SH").
pub fn p2wpkhOfPublicKey(pubkey: []const u8) HelperError![22]u8 {
    try checkCompressed(pubkey);
    return scriptP2wpkh(&hash160(pubkey));
}

/// P2SH-P2WPKH script (`OP_HASH160 hash160(0014{hash160(pk)}) OP_EQUAL`).
pub fn p2shP2wpkhOfPublicKey(pubkey: []const u8) HelperError![23]u8 {
    const redeem = try p2wpkhOfPublicKey(pubkey);
    return scriptP2sh(&hash160(&redeem));
}

/// P2SH script of a redeem script.
pub fn p2shOfRedeemScript(redeem: []const u8) HelperError![23]u8 {
    if (redeem.len > max_redeem_script_len) return error.RedeemScriptTooLarge;
    return scriptP2sh(&hash160(redeem));
}

/// P2WSH script of a witness script (`OP_0 SHA256(witness_script)`).
pub fn p2wshOfWitnessScript(witness_script: []const u8) HelperError![34]u8 {
    if (witness_script.len > max_witness_script_len) return error.WitnessScriptTooLarge;
    return scriptP2wsh(&sha256(witness_script));
}

/// P2SH-P2WSH script: the P2SH wrapper around `p2wshOfWitnessScript`.
pub fn p2shP2wshOfWitnessScript(witness_script: []const u8) HelperError![23]u8 {
    const redeem = try p2wshOfWitnessScript(witness_script);
    return scriptP2sh(&hash160(&redeem));
}

test {
    _ = @import("core_test.zig");
    _ = @import("unit_test.zig");
}
