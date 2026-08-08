# cbor

CBOR — Concise Binary Object Representation ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949))
codec, plus a minimal [COSE](https://www.rfc-editor.org/rfc/rfc9052) (RFC 9052) layer on top
(`cose.zig`): parsing `COSE_Key` (EC2/OKP) and `COSE_Sign1`, and building the `Sig_structure` bytes
a signer/verifier needs. This is the keystone that unblocks WebAuthn/FIDO2 (attestation objects,
authenticator data, COSE public keys) and any other CBOR/COSE-based wire format in this collection.

- **Model after:** RFC 8949 (CBOR) + RFC 9052 (COSE) — clean-room from the specs, no third-party
  implementation ported or consulted.
- **Platform:** any (pure logic, no I/O). **Role:** codec. **Concurrency:** reentrant (no shared
  state).
- **Deps:** none (std only).

Provenance: RFC 8949/9052 are public specifications (merger doctrine — CONVENTIONS.md §5); no
NOTICE entry needed.

## What it does

1. **Decode → `Value`.** `cbor.decode(allocator, bytes, .{})` parses one CBOR item into a tagged
   union covering all 8 RFC 8949 major types (uint / negint / byte-string / text-string / array /
   map / tag / simple+float — including `false`/`true`/`null`/`undefined` and `f16`/`f32`/`f64`),
   both definite- and indefinite-length forms. Indefinite byte/text-string chunks are concatenated
   and indefinite array/map items are collected into the same shape as their definite counterparts
   — `Value` does not record "was this indefinite on the wire" (see Deferred below).
2. **Encode ← `Value`.** `cbor.encode(allocator, value, .{})` always emits definite-length,
   shortest-form integers/lengths (RFC 8949 §4.1 "preferred serialization"). Pass
   `.{ .canonical = true }` to additionally sort every map's entries by the bytewise order of their
   *encoded* keys (RFC 8949 §4.2.1 core-deterministic encoding) — together this produces
   core-deterministic output.
3. **COSE (`cose.zig`).** `cose.parseKey`/`cose.encodeEc2Key`/`cose.encodeOkpKey` for `COSE_Key`
   (EC2/OKP public keys — the shape `ctap2pin`'s inline `PublicKey{x,y}` generalizes), and
   `cose.parseSign1`/`cose.encodeSign1`/`cose.sigStructure` for `COSE_Sign1` (RFC 9052 §4.2/§4.4).
   Everything routes through the `cbor.Value`/`decode`/`encode` above — no CBOR is hand-rolled a
   second time inside COSE. The actual signature algorithm (ECDSA/EdDSA/...) is out of scope —
   `sigStructure` gives you the exact bytes to feed to e.g. the sibling `p256`/`k256`/`ed448`
   modules' sign/verify.

## Untrusted-input hardening

`decode` parses hostile bytes (an attacker-controlled WebAuthn attestation object, a COSE message
off the wire) by design:

- **Nesting-depth cap** (`DecodeOptions.max_depth`, default 64) on array/map/tag recursion — a
  crafted deeply-nested input fails `error.DepthLimitExceeded` instead of blowing the stack.
- **Never pre-allocates from an attacker-declared length.** A byte/text-string length or an
  array/map element count is only ever checked against the *actual remaining input* before the
  allocator is touched; arrays/maps grow one decoded element at a time
  (`std.ArrayList.append`), so a bogus huge count is bounded by how many elements the input bytes
  can actually supply, not by the declared count. A declared length of `2^64-1` costs one bounds
  check, never an allocation attempt.
- **Fail-closed typed errors, never a panic/OOB.** Every malformed/truncated/trailing-garbage input
  maps to a `DecodeError` variant (`Truncated`, `Malformed`, `DepthLimitExceeded`,
  `TrailingGarbage`, `OutOfMemory`) — see `kat_test.zig`'s hostile-input tests and the
  arbitrary-bytes fuzz test.

## API

```zig
const cbor = @import("cbor");

// ── core codec ──
const Value = cbor.Value; // tagged union: uint/negint/bytes/text/array/map/tag/simple/bool/
                           // null_value/undefined_value/f16/f32/f64
const MapEntry = cbor.MapEntry; // { key: Value, value: Value }
const DecodeError = cbor.DecodeError; // error{ Truncated, Malformed, DepthLimitExceeded, TrailingGarbage, OutOfMemory }
const EncodeError = cbor.EncodeError; // Allocator.Error

fn decode(a: Allocator, bytes: []const u8, opts: cbor.DecodeOptions) DecodeError!Value;
fn encode(a: Allocator, value: Value, opts: cbor.EncodeOptions) EncodeError![]u8;
fn freeValue(a: Allocator, value: Value) void; // release a decoded tree without an arena

// value.toI64() -> ?i64   (uint/negint as a signed int, if it fits)
// Value.fromI64(i: i64) -> Value

// ── COSE ──
const cose = cbor.cose;
fn cose.parseKey(value: Value) cose.KeyError!cose.Key; // .ec2: Ec2Key | .okp: OkpKey
fn cose.encodeEc2Key(a: Allocator, k: cose.Ec2Key) Allocator.Error!Value;
fn cose.encodeOkpKey(a: Allocator, k: cose.OkpKey) Allocator.Error!Value;

fn cose.parseSign1(value: Value) cose.Sign1Error!cose.Sign1;
fn cose.encodeSign1(a: Allocator, s: cose.Sign1) Allocator.Error![]u8;
fn cose.sigStructure(a: Allocator, protected: []const u8, external_aad: []const u8, payload: []const u8) Allocator.Error![]u8;
```

Everything `decode` returns is allocated via the `allocator` you pass (arena-friendly, not
arena-required) — the input `bytes` need not outlive the call. Release the tree with
`freeValue(allocator, value)`, or by freeing the arena if that is what you passed; on an error
return there is nothing to release, `decode` unwinds its own partial tree. `cose.parseKey`/`parseSign1` don't allocate at all; their
returned slices borrow the `Value` tree you already decoded.

## Verify

```
zig build test-cbor
zig build test-cbor -Doptimize=ReleaseFast
zig fmt --check modules/cbor
```

## Deferred (backlog, not implemented here)

- **`Value` doesn't distinguish definite from indefinite length.** Decoding an indefinite
  byte-string/text-string/array/map produces the same shape as the definite form; `encode` always
  emits definite-length. A caller that specifically needs to reproduce an indefinite-length
  encoding byte-for-byte (rather than just its decoded value) isn't served by this module.
- **Float width is never re-minimized on encode.** `Value.f64`/`.f32`/`.f16` always re-encodes at
  that exact width; RFC 8949's "preferred serialization" additionally allows shrinking a float to
  the shortest width that round-trips exactly (e.g. `1.0` could be `f16` instead of `f64`) — not
  implemented. `canonical = true` therefore does not fully reach RFC 8949 §4.2.1's floating-point
  requirement, only its map-key-ordering requirement.
- **No bignum (RFC 8949 §3.4.3, tags 2/3) arithmetic.** A bignum tag decodes structurally (tag
  number + the byte-string payload, like any other tag) but this module does no big-integer math
  on it — consumers that need the numeric value convert the byte string themselves.
- **COSE scope:** only `COSE_Key` (EC2/OKP; RSA and symmetric key types return
  `error.UnsupportedKty`) and `COSE_Sign1`. No `COSE_Mac0`, `COSE_Encrypt0`, or full `COSE_Sign`
  (multi-signer). Private-key material (COSE label `-4`, `d`) is never parsed or emitted — this is
  a verifier/public-key-consumer layer, not a key-storage format.
