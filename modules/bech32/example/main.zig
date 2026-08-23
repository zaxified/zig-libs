// SPDX-License-Identifier: MIT

//! What a Bitcoin wallet does with `bech32`: turn a public key into a real
//! receive address on both layers this module ships (segwit v0 = P2WPKH,
//! segwit v1 = the Taproot output-key shape, plus the pre-segwit base58
//! P2PKH path), round-trip each address back through decode, and see a
//! pasted-address typo/network-mismatch/wrong-variant rejected by name.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator` here: per the module's own doc comment,
//! `bech32`/`segwit`/`base58` allocate nowhere at all (fixed-size stack
//! buffers throughout), so there is nothing for a leak detector to watch —
//! same posture as `modules/l2disco/example/main.zig`.
//!
//! `modules/bech32/src/kat_test.zig` already drives every official
//! BIP173/BIP350 vector (33 valid + 26 invalid) through this module; this
//! file deliberately does NOT restate that table. Instead every address
//! below is *computed* here from a public-key/program the way a caller
//! would, then checked against an external oracle:
//!
//!   - segwit v0 and the generic BIP173 layer: cross-checked by actually
//!     running the `bech32` PyPI package (Pieter Wuille's own BIP173
//!     reference code) — `bech32.encode`/`bech32.decode` and the low-level
//!     `bech32_encode`/`bech32_decode`.
//!   - segwit v1 (Taproot-shaped) and the generic BIP350 layer: that PyPI
//!     package (v1.2.0, checked at authoring time) is BIP173-only —
//!     `encode()` always XORs the checksum with BIP173's constant `1` and
//!     never with BIP350's `0x2bc830a3`, so it produces the WRONG checksum
//!     for any witver>=1 program (confirmed: it emits exactly the string
//!     BIP350's own "invalid segwit addresses" list flags as
//!     `error.InvalidVariant`). It is not a valid bech32m oracle. For the
//!     bech32m cases, this module's checksum was instead cross-checked by
//!     composing that same package's `bech32_polymod`/`bech32_hrp_expand`
//!     (the checksum math, identical for both variants) with BIP350's own
//!     published constant substituted in by hand from the spec text —
//!     ACTUALLY RUN, just not through a bech32m-aware upstream package
//!     (none was available offline).

const std = @import("std");
const bech32 = @import("bech32");

// secp256k1 base point G, compressed (0x02 || Gx) — a public, non-secret
// constant with no discrete log known to anyone, the standard "obviously
// not a real secret" throwaway pubkey in Bitcoin tooling examples.
const g_pubkey_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// SHA256("zig-libs bech32 example v1 throwaway") — a fresh 32-byte value,
// used only as an x-only-output-key-shaped witness program for the v1 leg
// below. Not derived from any real key; picked to differ from every
// program already present in `kat_vectors.zig`.
const xonly_hex = "a65d10985b25460df29550997c219a16544b4f345095cc480c457d44db96d093";

pub fn main() !void {
    var g_pubkey: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&g_pubkey, g_pubkey_hex) catch unreachable;

    // ── segwit v0 (P2WPKH): pubkey -> hash160 -> address -> decode ────────
    {
        var program: [20]u8 = undefined;
        bech32.base58.p2wpkhWitnessProgram(&g_pubkey, &program);

        const addr = try bech32.encodeSegwit("bc", 0, &program);
        // Cross-checked by actually running the `bech32` PyPI package:
        // `bech32.encode("bc", 0, hash160_bytes)` == this exact string
        // (which also happens to be BIP173's own P2WPKH test address, since
        // G is a famous enough constant that BIP173's authors used its
        // hash160 too — coincidence of a shared public constant, not a
        // copy of the vector table).
        const expected = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        std.debug.assert(std.mem.eql(u8, addr.slice(), expected));
        std.debug.print("v0 P2WPKH address: {s}\n", .{addr.slice()});

        const dec = try bech32.decodeSegwit("bc", addr.slice());
        std.debug.assert(dec.witver == 0);
        std.debug.assert(std.mem.eql(u8, dec.program(), &program));
        std.debug.print("  round-trip: witver={d} program={x}\n", .{ dec.witver, dec.program() });
    }

    // ── segwit v1 (Taproot-shaped): a fresh 32-byte program -> bech32m ────
    {
        var xonly: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&xonly, xonly_hex) catch unreachable;

        const addr = try bech32.encodeSegwit("bc", 1, &xonly);
        // Cross-checked (see file doc comment) via the PyPI package's own
        // polymod/hrp-expand plus BIP350's published 0x2bc830a3 constant.
        const expected = "bc1p5ew3pxzmy4rqmu542zvhcgv6ze2ykne52z2ucjqvg475fkuk6zfsy503zq";
        std.debug.assert(std.mem.eql(u8, addr.slice(), expected));
        std.debug.print("v1 taproot-shaped address: {s}\n", .{addr.slice()});

        const dec = try bech32.decodeSegwit("bc", addr.slice());
        std.debug.assert(dec.witver == 1);
        std.debug.assert(std.mem.eql(u8, dec.program(), &xonly));
        std.debug.print("  round-trip: witver={d} program={x}\n", .{ dec.witver, dec.program() });
    }

    // ── generic bech32/bech32m layer, no witness-version notion at all ────
    // (segwit.zig is one consumer of bech32.zig, but the generic codec is
    // documented as "usable standalone" — e.g. for non-Bitcoin bech32-based
    // formats like Lightning invoices or Nostr's npub/nsec.)
    {
        const data = [_]u5{ 3, 1, 4, 1, 5, 9, 2, 6 };
        const enc = try bech32.encode("example", &data, .bech32);
        // ACTUALLY RUN: PyPI `bech32.bech32_encode("example", [3,1,4,1,5,9,2,6])`.
        std.debug.assert(std.mem.eql(u8, enc.slice(), "example1rpyp9fzxtfdz37"));
        const dec = try bech32.decode(enc.slice());
        std.debug.assert(dec.encoding == .bech32);
        std.debug.assert(std.mem.eql(u8, dec.hrp(), "example"));
        std.debug.assert(std.mem.eql(u5, dec.data(), &data));
        std.debug.print("generic bech32: {s}\n", .{enc.slice()});
    }
    {
        const data = [_]u5{ 2, 7, 1, 8, 2, 8 };
        const enc = try bech32.encode("zlib", &data, .bech32m);
        // ACTUALLY RUN: PyPI package's polymod/hrp_expand + BIP350 constant
        // 0x2bc830a3 substituted by hand from the spec (see doc comment).
        std.debug.assert(std.mem.eql(u8, enc.slice(), "zlib1z8pgzg3x4fet"));
        const dec = try bech32.decode(enc.slice());
        std.debug.assert(dec.encoding == .bech32m);
        std.debug.print("generic bech32m: {s}\n", .{enc.slice()});
    }

    // ── base58 P2PKH: the pre-segwit path, same pubkey, testnet version ───
    {
        var addr_buf: [64]u8 = undefined;
        const addr = try bech32.base58.encodeP2PKH(0x6f, &g_pubkey, &addr_buf);
        std.debug.print("testnet P2PKH address: {s}\n", .{addr});

        var payload_buf: [bech32.base58.max_payload_len]u8 = undefined;
        const payload = try bech32.base58.checkDecode(addr, &payload_buf);
        std.debug.assert(payload.len == bech32.base58.p2pkh_payload_len);
        std.debug.assert(payload[0] == 0x6f);

        var program: [20]u8 = undefined;
        bech32.base58.p2wpkhWitnessProgram(&g_pubkey, &program);
        std.debug.assert(std.mem.eql(u8, payload[1..], &program));
    }

    // ── negative paths: a pasted/received address, five distinct defects ──
    // Each must fail by the SPECIFIC named error a wallet would branch on,
    // never a blanket catch.

    // (1) Right address, wrong network: mainnet caller expects "bc", this
    // string is the testnet HRP variant of the same v0 address shape.
    {
        var program: [20]u8 = undefined;
        bech32.base58.p2wpkhWitnessProgram(&g_pubkey, &program);
        const tb_addr = try bech32.encodeSegwit("tb", 0, &program);
        if (bech32.decodeSegwit("bc", tb_addr.slice())) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidHrp => std.debug.print("wrong network: InvalidHrp (expected)\n", .{}),
            else => return err,
        }
    }

    // (2) A display/clipboard bug re-cases one character of an otherwise
    // valid address — BIP173 requires an all-same-case string.
    {
        var program: [20]u8 = undefined;
        bech32.base58.p2wpkhWitnessProgram(&g_pubkey, &program);
        const addr = try bech32.encodeSegwit("bc", 0, &program);
        var corrupted = addr.buf;
        corrupted[10] = std.ascii.toUpper(corrupted[10]);
        if (bech32.decodeSegwit("bc", corrupted[0..addr.len])) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.MixedCase => std.debug.print("re-cased paste: MixedCase (expected)\n", .{}),
            else => return err,
        }
    }

    // (3) A single mistyped character in the checksum tail (e.g. 'q' <->
    // 'p' on an adjacent keyboard-map position) — a typo, not a re-casing.
    {
        var program: [20]u8 = undefined;
        bech32.base58.p2wpkhWitnessProgram(&g_pubkey, &program);
        const addr = try bech32.encodeSegwit("bc", 0, &program);
        var typo = addr.buf;
        const last = typo[addr.len - 1];
        typo[addr.len - 1] = for (bech32.charset) |c| {
            if (c != last) break c;
        } else unreachable;
        if (bech32.decodeSegwit("bc", typo[0..addr.len])) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidChecksum => std.debug.print("checksum typo: InvalidChecksum (expected)\n", .{}),
            else => return err,
        }
    }

    // (4) A v1+ program checksummed as plain bech32 instead of bech32m —
    // BIP350's headline consensus rule. Built here via the generic codec
    // directly (the public composition a caller would use to construct a
    // deliberately-wrong-variant fixture of their own): take the correctly
    // bech32m-checksummed v1 address, split it back into hrp+quintets with
    // the generic decoder, then re-encode those SAME quintets with the
    // wrong `Encoding`. Same program as the v1 leg above — not any literal
    // string already in kat_vectors.zig.
    {
        var xonly: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&xonly, xonly_hex) catch unreachable;

        const good = try bech32.encodeSegwit("bc", 1, &xonly);
        const parts = try bech32.decode(good.slice());
        std.debug.assert(parts.encoding == .bech32m);

        const wrong_variant = try bech32.encode(parts.hrp(), parts.data(), .bech32);
        if (bech32.decodeSegwit("bc", wrong_variant.slice())) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidVariant => std.debug.print("v1 checksummed as bech32 (not bech32m): InvalidVariant (expected)\n", .{}),
            else => return err,
        }
    }

    // (5) The base58 layer's own checksum, corrupted the same way (5): the
    // 4-byte double-SHA256 tail, not the bech32 BCH tail.
    {
        var addr_buf: [64]u8 = undefined;
        const addr = try bech32.base58.encodeP2PKH(0x6f, &g_pubkey, &addr_buf);
        var tampered_buf: [64]u8 = undefined;
        @memcpy(tampered_buf[0..addr.len], addr);
        const last = tampered_buf[addr.len - 1];
        tampered_buf[addr.len - 1] = for (bech32.base58.alphabet) |c| {
            if (c != last) break c;
        } else unreachable;

        var payload_buf: [bech32.base58.max_payload_len]u8 = undefined;
        if (bech32.base58.checkDecode(tampered_buf[0..addr.len], &payload_buf)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.ChecksumMismatch => std.debug.print("base58 checksum typo: ChecksumMismatch (expected)\n", .{}),
            else => return err,
        }
    }
}
