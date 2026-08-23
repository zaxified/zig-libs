// SPDX-License-Identifier: MIT

//! What a Bitcoin wallet does with `bip32`: turn a fresh entropy source into
//! a mnemonic, derive an HD account down to a receive address, serialize
//! and re-parse the extended keys, then run the BIP-44 "share only the
//! account xpub" pattern — deriving further receive addresses from a
//! public-only key, which is the whole reason BIP-32 keeps normal
//! derivation separate from hardened.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: `bip39.zig`/`bip32.zig` allocate nowhere
//! (fixed-size stack buffers throughout, documented in `root.zig`), so
//! there is nothing for a leak detector to watch here.
//!
//! `modules/bip32/src/kat_test.zig` already drives BIP-32's official Test
//! Vectors 1-5 and the BIP-39 Trezor vector set (fixed, patterned entropy:
//! `0000...`, `7f7f7f...`, `ffff...`, passphrase always `"TREZOR"`) through
//! this module; this file does NOT restate that table. Every value below is
//! computed here from FRESH inputs (different entropy, a different
//! passphrase, a real BIP-44 path) the way a caller would, then checked
//! against an external oracle:
//!
//!   - BIP-39 (entropy -> mnemonic, checksum validity): ACTUALLY RUN against
//!     the `mnemonic` PyPI package (Trezor's own reference implementation).
//!   - BIP-32 (seed -> master -> derived xprv/xpub): ACTUALLY RUN against a
//!     from-spec Python re-implementation assembled from `hmac`/`hashlib`
//!     (HMAC-SHA512), the `ecdsa` PyPI package (secp256k1 point
//!     multiplication only — no BIP-32 logic borrowed from it), and the
//!     `base58` PyPI package (Base58Check). That Python implementation was
//!     first sanity-checked against BIP-32's own published Test Vector 1
//!     (master key from seed `000102...0f`) before being trusted for the
//!     fresh scenario below.

const std = @import("std");
const bip32 = @import("bip32");
const bech32 = @import("bech32");

// Fresh entropy, distinct from every pattern in the embedded Trezor vector
// table (`00000000..`, `7f7f7f7f..`, `80808080..`, `ffffffff..`).
const entropy_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const passphrase = "zig-libs example";
// m/44'/0'/0'/0/0 — BIP-44, Bitcoin mainnet, account 0, external chain,
// address index 0.
const account_path = "m/44'/0'/0'";
const receive_path = "m/44'/0'/0'/0/0";

pub fn main() !void {
    // ── BIP-39: entropy -> mnemonic -> seed ────────────────────────────────

    var entropy: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&entropy, entropy_hex) catch unreachable;

    var mnemonic_buf: [bip32.mnemonic.max_mnemonic_len]u8 = undefined;
    const phrase = try bip32.mnemonic.entropyToMnemonic(&entropy, &mnemonic_buf);
    // ACTUALLY RUN: Python `Mnemonic("english").to_mnemonic(entropy)`.
    const expected_phrase = "payment noodle vivid slogan gather metal pilot enact fragile hip physical canvas";
    std.debug.assert(std.mem.eql(u8, phrase, expected_phrase));
    std.debug.print("mnemonic: {s}\n", .{phrase});

    try bip32.mnemonic.validateMnemonic(phrase);

    var seed: [64]u8 = undefined;
    try bip32.mnemonic.mnemonicToSeed(phrase, passphrase, &seed);
    // ACTUALLY RUN: Python `Mnemonic.to_seed(phrase, passphrase)`.
    const expected_seed_hex = "df084a26af4b6f0502d1311f20225fbe7181e5d8676cc0c5d28f06f196d1fff0bba709cddcd4818f42b5b92d93d488b887366e068dc9abf37833223674cb21ef";
    var expected_seed: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected_seed, expected_seed_hex) catch unreachable;
    std.debug.assert(std.mem.eql(u8, &seed, &expected_seed));

    // ── BIP-32: seed -> master -> account -> receive address ──────────────

    var master = try bip32.masterFromSeed(&seed);
    defer master.deinit();
    std.debug.assert(master.isMaster());

    var path_buf: [bip32.max_path_depth]u32 = undefined;
    const receive_indices = try bip32.parsePath(receive_path, &path_buf);
    var receive_key = try bip32.derivePath(master, receive_indices);
    defer receive_key.deinit();

    var xprv_buf: [bip32.max_serialized_len]u8 = undefined;
    const xprv = try bip32.serializePriv(receive_key, &xprv_buf);
    // ACTUALLY RUN: the from-spec Python re-implementation (see file doc
    // comment), sanity-checked against BIP-32 Test Vector 1 first.
    const expected_xprv = "xprvA44AZhTuxqQYC15kQX4LrXdNFZaMZMaHXdgMS76DnTR4dASrhsrr7RscrS6UatP3v7oXTu8RvjPwQYzZPyNyoUD9uahvacPajSmyMyx7a59";
    std.debug.assert(std.mem.eql(u8, xprv, expected_xprv));
    std.debug.print("receive xprv: {s}\n", .{xprv});

    const receive_pub = try bip32.neuter(receive_key);
    var xpub_buf: [bip32.max_serialized_len]u8 = undefined;
    const xpub = try bip32.serializePub(receive_pub, &xpub_buf);
    const expected_xpub = "xpub6H3WyCzooCxqQVADWYbMDfa6obQqxpJ8trbxEVVqLnx3Vxn1FRB6fEC6hjtXLJ6Djp7fkwxT1Qd1GgXLahjtcN8eSV4e94u8Jt3PCwEfGe8";
    std.debug.assert(std.mem.eql(u8, xpub, expected_xpub));
    std.debug.print("receive xpub: {s}\n", .{xpub});

    // Round-trip both through the untrusted-text parser a wallet uses when
    // IMPORTING a key a user pasted in.
    {
        const parsed = try bip32.parseExtended(xprv);
        std.debug.assert(parsed == .private);
        std.debug.assert(std.mem.eql(u8, &parsed.private.privkey, &receive_key.privkey));
    }
    {
        const parsed = try bip32.parseExtended(xpub);
        std.debug.assert(parsed == .public);
        std.debug.assert(std.mem.eql(u8, &parsed.public.pubkey, &receive_pub.pubkey));
    }

    // ── BIP-44 watch-only pattern: share the ACCOUNT xpub, derive further
    // receive addresses from it with no private key in reach ─────────────
    {
        const account_indices = try bip32.parsePath(account_path, &path_buf);
        var account_key = try bip32.derivePath(master, account_indices);
        defer account_key.deinit();
        const account_pub = try bip32.neuter(account_key);

        // The public helper a wallet UI uses to label "derived from key
        // with fingerprint XXXXXXXX" — checked against the actual parent
        // link BIP-32 recorded on a direct child of master (fingerprints
        // are only meaningful one level up, not across the full account path).
        const master_pub = try bip32.neuter(master);
        var purpose_key = try bip32.ckdPriv(master, bip32.hardened_offset + 44);
        defer purpose_key.deinit();
        std.debug.assert(std.mem.eql(u8, &bip32.fingerprint(master_pub.pubkey), &purpose_key.parent_fingerprint));

        // external chain (index 0) and receive address 0, both via
        // public-only `ckdPub` — no `account_key.privkey` touched below.
        const external_pub = try bip32.ckdPub(account_pub, 0);
        const receive_pub_via_watch_only = try bip32.ckdPub(external_pub, 0);

        // Must agree with the fully-private derivation above (m/44'/0'/0'/0/0).
        std.debug.assert(std.mem.eql(u8, &receive_pub_via_watch_only.pubkey, &receive_pub.pubkey));
        std.debug.assert(std.mem.eql(u8, &receive_pub_via_watch_only.chain_code, &receive_pub.chain_code));
        std.debug.print("watch-only receive[0] pubkey matches privately-derived: {x}\n", .{receive_pub_via_watch_only.pubkey});

        // A second receive address, still with no private key: this is the
        // entire point of a watch-only xpub.
        const receive1_pub = try bip32.ckdPub(external_pub, 1);
        std.debug.print("watch-only receive[1] pubkey: {x}\n", .{receive1_pub.pubkey});

        // The watch-only wallet's defining restriction: it cannot extend a
        // HARDENED path, because that needs the private key it deliberately
        // does not have.
        if (bip32.ckdPub(account_pub, bip32.hardened_offset + 0)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.HardenedRequiresPrivateKey => std.debug.print("watch-only hardened derivation: HardenedRequiresPrivateKey (expected)\n", .{}),
            else => return err,
        }
    }

    // ── negative paths: named errors, never a blanket catch ───────────────

    // (1) A mistyped last word of a real mnemonic — the checksum word — is
    // still a wordlist entry, so only the checksum math catches it.
    {
        const last_space = std.mem.lastIndexOfScalar(u8, phrase, ' ').?;
        var tampered_buf: [bip32.mnemonic.max_mnemonic_len]u8 = undefined;
        @memcpy(tampered_buf[0 .. last_space + 1], phrase[0 .. last_space + 1]);
        const replacement = if (std.mem.eql(u8, phrase[last_space + 1 ..], "canvas")) "canyon" else "canvas";
        @memcpy(tampered_buf[last_space + 1 ..][0..replacement.len], replacement);
        const tampered = tampered_buf[0 .. last_space + 1 + replacement.len];

        if (bip32.mnemonic.validateMnemonic(tampered)) {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidChecksum => std.debug.print("mistyped checksum word: InvalidChecksum (expected)\n", .{}),
            else => return err,
        }
    }

    // (2) A word that just isn't in the wordlist at all (fat-fingered): the
    // first word ("payment") replaced outright with a non-word.
    {
        var tampered_buf: [bip32.mnemonic.max_mnemonic_len]u8 = undefined;
        const n = phrase.len;
        const first_space = std.mem.indexOfScalar(u8, phrase, ' ').?;
        const replacement = "notaword";
        @memcpy(tampered_buf[0..replacement.len], replacement);
        @memcpy(tampered_buf[replacement.len..][0 .. n - first_space], phrase[first_space..]);
        const tampered = tampered_buf[0 .. replacement.len + n - first_space];

        if (bip32.mnemonic.validateMnemonic(tampered)) {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.WordNotInList => std.debug.print("unknown word: WordNotInList (expected)\n", .{}),
            else => return err,
        }
    }

    // (3) A path string with a stray non-digit character (a scientific-
    // notation-shaped typo `1e3`, which `std.fmt.parseUnsigned` on its own
    // would actually accept as valid Zig-number-literal leniency guards
    // against — see the module's own F5 regression for the digit-only check
    // this trips).
    {
        var out: [bip32.max_path_depth]u32 = undefined;
        if (bip32.parsePath("m/44'/0'/1e3/0/0", &out)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidPathSegment => std.debug.print("path with 1e3 typo: InvalidPathSegment (expected)\n", .{}),
            else => return err,
        }
    }

    // (4) A path deeper than the caller's own output buffer.
    {
        var small_out: [3]u32 = undefined;
        if (bip32.parsePath("m/1/2/3/4", &small_out)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.PathTooDeep => std.debug.print("path deeper than caller buffer: PathTooDeep (expected)\n", .{}),
            else => return err,
        }
    }

    // (5) A pre-hardened-offset index that doesn't fit in 31 bits.
    {
        var out: [bip32.max_path_depth]u32 = undefined;
        if (bip32.parsePath("m/3000000000", &out)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.IndexOutOfRange => std.debug.print("index >= 2^31: IndexOutOfRange (expected)\n", .{}),
            else => return err,
        }
    }

    // (6) A single-character checksum typo on OUR freshly-derived xprv (not
    // a table literal) — the everyday "fat-fingered a paste" case.
    {
        var typo = xprv_buf;
        const last = typo[xprv.len - 1];
        typo[xprv.len - 1] = for (bech32.base58.alphabet) |c| {
            if (c != last) break c;
        } else unreachable;

        if (bip32.parseExtended(typo[0..xprv.len])) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.ChecksumMismatch => std.debug.print("xprv checksum typo: ChecksumMismatch (expected)\n", .{}),
            else => return err,
        }
    }

    // (7) A real extended key from the WRONG network: this module only
    // knows the mainnet version bytes, so a testnet `tpub` (version
    // 0x043587CF, the well-known BIP-32 testnet-public constant) must be
    // rejected by version, not silently accepted as if it were mainnet.
    {
        var payload: [bip32.serialized_payload_len]u8 = undefined;
        std.mem.writeInt(u32, payload[0..4], 0x043587CF, .big); // testnet tpub
        payload[4] = 0; // depth
        @memset(payload[5..9], 0); // parent fingerprint
        @memset(payload[9..13], 0); // child number
        @memset(payload[13..45], 0x11); // chain code (arbitrary, not validated before version check)
        _ = std.fmt.hexToBytes(payload[45..78], "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") catch unreachable;

        var addr_buf: [bip32.max_serialized_len]u8 = undefined;
        const fake_tpub = try bech32.base58.checkEncode(&payload, &addr_buf);

        if (bip32.parseExtended(fake_tpub)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.UnknownVersion => std.debug.print("testnet tpub pasted into mainnet parser: UnknownVersion (expected)\n", .{}),
            else => return err,
        }
    }
}
