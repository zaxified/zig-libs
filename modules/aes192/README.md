# aes192

**The AES-192 block cipher that Zig 0.16's std does not ship.** `std.crypto.core.aes` has
`Aes128` and `Aes256` only, so every AES mode in this collection (CBC, key wrap, GCM, JWE,
XML-Enc, SSH `aes192-ctr`) refused 192-bit keys. This module adds the third member of that
family with the same declarations — `key_bits`, `rounds`, `block`, `initEnc`, `initDec`, and
contexts with `encrypt`/`xor`/`encryptWide`/`xorWide`/`decrypt`/`decryptWide` — so code written
generically over std's `Aes128`/`Aes256` (including `std.crypto.core.modes.ctr`) takes
`Aes192` unchanged. Only the key expansion (FIPS-197 §5.2, Nk = 6, Nr = 12) is new; every round
runs on std's own primitive for the target: AES-NI on amd64, ARMv8 Crypto on arm64, std's
software path elsewhere.

- **Model after:** FIPS-197 §5.2, and std's `Aes128`/`Aes256` API shape.
- **Platform:** any (hardware AES via std where the target has it, software otherwise).
  **Role:** crypto primitive. **Concurrency:** reentrant. **Deps:** none (`std.crypto.core.aes`).

Provenance: original work of the zig-libs authors (MIT), written from FIPS-197 — a public
standard, not a copyrightable work. The test vectors are NIST's (FIPS-197 appendices, CAVP
AESAVS, SP 800-38A; US Government works). See `SPEC.md`.

## Usage

```zig
const aes192 = @import("aes192");
const Aes192 = aes192.Aes192;

const key: [24]u8 = ...;

// Dead-stack-clean form (no key copy in your frame): the *Into twins.
var enc: aes192.Aes192EncryptCtx = undefined;
Aes192.initEncInto(&enc, &key);
defer enc.wipe();

var block: [16]u8 = ...;
enc.encrypt(&block, &block);

var dec: aes192.Aes192DecryptCtx = undefined;
Aes192.initDecInto(&dec, &key);
defer dec.wipe();
dec.decrypt(&block, &block);

// Any std mode generic over a block-cipher context:
std.crypto.core.modes.ctr(aes192.Aes192EncryptCtx, enc, dst, src, iv, .big);
```

## API

```zig
pub const Block = std.crypto.core.aes.Block;
pub const has_hardware_support: bool;  // std's flag: AES-NI / ARMv8 Crypto in this build
pub const key_length = 24;
pub const rounds = 12;

pub const Aes192 = struct {
    pub const key_bits = 192;
    pub const rounds = 12;
    pub const block = Block;
    pub fn initEnc(key: [24]u8) Aes192EncryptCtx;          // std shape
    pub fn initDec(key: [24]u8) Aes192DecryptCtx;          // std shape
    pub fn initEncInto(out: *Aes192EncryptCtx, key: *const [24]u8) void;
    pub fn initDecInto(out: *Aes192DecryptCtx, key: *const [24]u8) void;
};

pub const Aes192EncryptCtx = struct {   // = std's AesEncryptCtx(Aes) shape
    pub const block = Block;
    pub const block_length = 16;
    key_schedule: KeySchedule,           // .round_keys: [13]Block
    pub fn init(key: [24]u8) Aes192EncryptCtx;
    pub fn initInto(out: *Aes192EncryptCtx, key: *const [24]u8) void;
    pub fn encrypt(ctx, dst: *[16]u8, src: *const [16]u8) void;
    pub fn xor(ctx, dst: *[16]u8, src: *const [16]u8, counter: [16]u8) void;
    pub fn encryptWide(ctx, comptime n: usize, dst: *[16 * n]u8, src: *const [16 * n]u8) void;
    pub fn xorWide(ctx, comptime n: usize, dst, src, counters: [16 * n]u8) void;
    pub fn wipe(ctx: *Aes192EncryptCtx) void;
};

pub const Aes192DecryptCtx = struct {   // = std's AesDecryptCtx(Aes) shape
    pub fn initFromEnc(ctx: Aes192EncryptCtx) Aes192DecryptCtx;
    pub fn init(key: [24]u8) Aes192DecryptCtx;
    pub fn initInto(out: *Aes192DecryptCtx, key: *const [24]u8) void;
    pub fn decrypt(ctx, dst: *[16]u8, src: *const [16]u8) void;
    pub fn decryptWide(ctx, comptime n: usize, dst, src) void;
    pub fn wipe(ctx: *Aes192DecryptCtx) void;
};
```

A context holds the round keys — the key, in effect. It is never written after `init`, so one
context may be shared by threads; call `wipe` when the key is retired (nothing else clears it).

Without hardware AES (`has_hardware_support == false`) the rounds are std's table-based
software path with cache-line masking, exactly as for std's `Aes128`/`Aes256`: not constant
time against a co-located cache attacker. See `SPEC.md`, *Constant-time contract*.

## Tests

`zig build test-aes192`. Anchors: FIPS-197 Appendix C.2 (cipher, inverse cipher, both round-key
traces) and A.2 (all 52 expanded words), all 720 NIST CAVP AESAVS AES-192 ECB vectors (GFSbox,
KeySbox, VarKey, VarTxt, MMT; encrypt and decrypt), SP 800-38A F.1.3/F.5.5 through
`std.crypto.core.modes.ctr`, and the FIPS-197 S-box for all 256 inputs. A textbook FIPS-197
model in `src/model_test.zig` is the fuzz harness's differential oracle
(`AES192_FUZZ=<runs>`, testkit's deterministic driver).
