# cbor

CBOR — Concise Binary Object Representation ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949))
codec, plus a minimal [COSE](https://www.rfc-editor.org/rfc/rfc9052) (RFC 9052) layer on top
(`cose.zig`): parsing `COSE_Key` (EC2/OKP/AKP) and `COSE_Sign1`, and building the `Sig_structure` bytes
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
   `.{ .canonical = true }` for RFC 8949 §4.2.1 Core Deterministic Encoding: every map's entries
   sorted by the bytewise order of their *encoded* keys, and every float in the shortest width that
   keeps its value (`1.5` → `f93e00`; every NaN → `f97e00`). `.{ .shortest_floats = true }` asks
   for the float rule alone.
3. **Strict decoding.** `DecodeOptions.reject_duplicate_keys` (data-model equal keys, RFC 8949
   §5.6 → `error.DuplicateKey`), `.reject_indefinite`, and `.deterministic` (only the canonical
   encoding of the value passes: shortest heads and floats, sorted keys, definite lengths →
   `error.NotDeterministic`); `cbor.strict_options` turns all three on — what a COSE/CTAP2/dCBOR
   verifier wants before it hashes or signs bytes.
4. **CBOR Sequences** (RFC 8742): `cbor.Sequence.init(a, bytes, opts)`, `next()` item by item.
5. **Diagnostic notation** (RFC 8949 §8): `cbor.diagnostic(a, value)` / `cbor.writeDiagnostic(w,
   value)` — `[1, {"a": h'0102'}, 1(1363896240)]`, exactly as RFC 8949 Appendix A prints.
6. **Streaming** (`cbor.stream`): `cbor.Reader` pulls tokens out of a slice with no allocation
   (strings borrowed from the input; a token cut short is `error.Truncated` with nothing consumed,
   so data arriving in pieces can be retried), `skipValue`/`rawValue` walk one whole item with
   `decode`'s exact verdicts; `cbor.Writer` pushes heads and items onto any `*std.Io.Writer` — a
   caller buffer via `std.Io.Writer.fixed`, a file, a socket.
7. **Typed mapping** (`cbor.typed`): `typed.decode(T, gpa, bytes, .{})` → `Parsed(T)` and
   `typed.encode(gpa, x, .{})` for bools, integers, floats, strings, byte arrays, slices, arrays,
   tuples, structs (keys by field name or `pub const cbor_options = .{ .keys = .{ .alg = 3 } }`,
   integer keys negative too), optionals, enums, tagged unions, pointers, and raw `Value`s.
   Missing / duplicate / unknown fields, range, length and type mismatches are typed errors; what
   the mapping allocates is capped (`max_alloc_bytes`, default 64 MiB).
8. **COSE (`cose.zig`).** `cose.parseKey`/`cose.encodeEc2Key`/`cose.encodeOkpKey` for `COSE_Key`
   (EC2/OKP public keys — the shape `ctap2pin`'s inline `PublicKey{x,y}` generalizes — plus AKP,
   RFC 9964's post-quantum key type, whose ML-DSA parameter set comes from the REQUIRED `alg` and
   is never inferred from the key length), and
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
  `TrailingGarbage`, `DuplicateKey`, `NotDeterministic`, `OutOfMemory`) — see `kat_test.zig`'s
  hostile-input tests and the fuzz harnesses.
- **Deterministic fuzz driver** (`fuzz_test.zig`, `CBOR_FUZZ=<runs>[,<seed>]`): random trees,
  encoded and damaged at heads, arguments and copied token ranges, through every parser — the
  reader must reach `decode`'s verdict, `deterministic` must accept exactly the canonical
  encodings, `reject_duplicate_keys` must agree with an independent data-model equality, no leak.
  300 seeds run in every ordinary test run.

## API

```zig
const cbor = @import("cbor");

// ── core codec ──
const Value = cbor.Value; // tagged union: uint/negint/bytes/text/array/map/tag/simple/bool/
                           // null_value/undefined_value/f16/f32/f64
const MapEntry = cbor.MapEntry; // { key: Value, value: Value }
const DecodeError = cbor.DecodeError; // error{ Truncated, Malformed, DepthLimitExceeded, TrailingGarbage,
                                      //        DuplicateKey, NotDeterministic, OutOfMemory }
const EncodeError = cbor.EncodeError; // Allocator.Error

fn decode(a: Allocator, bytes: []const u8, opts: cbor.DecodeOptions) DecodeError!Value;
// One item from the front + the bytes it took; the rest is the caller's (no TrailingGarbage):
fn decodePrefix(a: Allocator, bytes: []const u8, opts: cbor.DecodeOptions) DecodeError!cbor.Prefix; // { value, len }
fn encode(a: Allocator, value: Value, opts: cbor.EncodeOptions) EncodeError![]u8;
fn freeValue(a: Allocator, value: Value) void; // release a decoded tree without an arena

// value.toI64() -> ?i64   (uint/negint as a signed int, if it fits)
// Value.fromI64(i: i64) -> Value
// DecodeOptions{ .max_depth = 64, .reject_duplicate_keys, .reject_indefinite, .deterministic }
// cbor.strict_options    (all three)
// EncodeOptions{ .canonical, .shortest_floats }

// ── sequences, diagnostic notation ──
var seq = cbor.Sequence.init(a, bytes, opts); // while (try seq.next()) |v| { ...; cbor.freeValue(a, v); }
fn diagnostic(a: Allocator, value: Value) Allocator.Error![]u8;
fn writeDiagnostic(w: *std.Io.Writer, value: Value) std.Io.Writer.Error!void;

// ── streaming (no allocation) ──
var r = cbor.Reader.init(bytes); // r.next() -> ?Token, r.peek(), r.skipValue(max_depth), r.rawValue(max_depth)
const cw = cbor.Writer.init(w);  // uint int negint bytes text beginArray(?n) beginMap(?n) beginBytes
                                 // beginText end tag boolean null_ undefined_ simple float float16/32/64 value
fn shortestFloat(x: f64) cbor.FloatWidth; fn head(major: u3, arg: u64) cbor.Head;

// ── typed ──
fn typed.decode(comptime T: type, gpa: Allocator, bytes: []const u8, o: typed.Options) typed.Error!typed.Parsed(T);
fn typed.decodeLeaky(comptime T: type, arena: Allocator, bytes: []const u8, o: typed.Options) typed.Error!T;
fn typed.fromValue(comptime T: type, arena: Allocator, v: Value, o: typed.Options) typed.Error!T;
fn typed.toValue(arena: Allocator, x: anytype) Allocator.Error!Value;
fn typed.encode(gpa: Allocator, x: anytype, o: cbor.EncodeOptions) Allocator.Error![]u8;

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
CBOR_FUZZ=150000,0 <test binary built with --test-filter "fuzz driver">   # fuzz verdict
```

Vector recipes: `tools/gen_diag_vectors.py` (RFC 8949 Appendix A from the RFC text) and
`tools/gen_cbor2_vectors.py` (Python cbor2 6.1.5 as a black-box oracle: float widths, whole
trees, duplicate-key and indefinite-length verdicts).

## Deferred (backlog, not implemented here)

- **`Value` doesn't distinguish definite from indefinite length.** Decoding an indefinite
  byte-string/text-string/array/map produces the same shape as the definite form; `encode` always
  emits definite-length. A caller that specifically needs to reproduce an indefinite-length
  encoding byte-for-byte (rather than just its decoded value) isn't served by this module.
- **NaN payloads under `canonical`/`shortest_floats`.** Every NaN is written as `f97e00`; a
  payload is not kept (RFC 8949 §4.2.2 leaves NaN to the protocol; dCBOR and cbor2 do the same).
- **Bignum-aware preferred serialization.** RFC 8949 §3.4.3 asks a bignum that fits 64 bits to
  be encoded as a plain integer; `canonical` leaves tags 2/3 as given.
- **Typed mapping limits.** No integers wider than 64 bits, no sentinel-terminated slices, no
  untagged unions; tags are not mapped to Zig types (use a `Value` field).
- **No bignum (RFC 8949 §3.4.3, tags 2/3) arithmetic.** A bignum tag decodes structurally (tag
  number + the byte-string payload, like any other tag) but this module does no big-integer math
  on it — consumers that need the numeric value convert the byte string themselves.
- **COSE scope:** only `COSE_Key` (EC2/OKP/AKP; RSA and symmetric key types return
  `error.UnsupportedKty`) and `COSE_Sign1`. No `COSE_Mac0`, `COSE_Encrypt0`, or full `COSE_Sign`
  (multi-signer) — libcbor, the reference, has no COSE at all, and no consumer in the collection
  needs them yet. Private-key material (COSE label `-4` `d` for EC2/OKP, `-2` `priv` for AKP) is
  never parsed or emitted — this is a verifier/public-key-consumer layer, not a key-storage
  format.
