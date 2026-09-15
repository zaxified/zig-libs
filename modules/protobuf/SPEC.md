# protobuf — spec

Design + threat notes for auditors. Usage: see ./README.md. Provenance: the Protocol Buffers
encoding specification is a public specification (CONVENTIONS.md §5 merger doctrine — no NOTICE
entry); clean-room, no third-party source ported. The Python `protobuf` package is executed as a
black-box compatibility oracle only, which CONVENTIONS.md §5 explicitly says needs no entry.

## Decisions

### No `.proto` compiler, and none planned here

Generating Zig from `.proto` files is a **separate project**, deliberately out of scope — this is a
decision, not an omission. A code generator is a parser for a second language, a resolver for its
import graph, a build-system integration, and a lifetime problem of its own; none of that is the
wire format, and all of it would have to be maintained against `protoc`'s behaviour rather than
against the encoding spec. Keeping the codec generator-free also means the module has exactly one
external contract to be judged against — the bytes — which is the contract the reference
implementation can check for us.

What replaces it: the schema is derived at comptime from a plain Zig struct plus a `pb_fields`
descriptor. If a generator is ever built, its natural output is exactly these structs, so it would
sit on top of this module rather than replace it.

### The descriptor names the type; the Zig type names the cardinality

Three designs were considered.

1. **Everything in the descriptor** (`.{ .number = 1, .kind = .int32, .repeated = true }`). Rejected:
   the Zig field type and the descriptor then both encode cardinality and can disagree, and the
   disagreement is only discoverable at run time, on the wire, at the far end.
2. **A wrapper type per field** (`Repeated(i32)`, `Optional(i32)`). Rejected: it makes the message
   struct unusable as a plain Zig value — every read becomes `.get()`, and a literal stops being a
   literal. The struct being *ordinary* is the point.
3. **Chosen:** the descriptor names the proto type only; `T` / `?T` / `[]const T` carry singular /
   explicit-presence / repeated. There is exactly one place each fact lives, and every mismatch
   (`.sint64` on an `f32`, `.message` on a non-message, a singular non-optional message) is a
   compile error naming the field.

`.message` singular is required to be `?T` because proto3 messages always have explicit presence;
making the common case spell it out is cheaper than a silent semantic difference from every other
implementation.

### Unknown-field preservation is opt-in by declaring a sink

Dropping unknown fields silently breaks proxying and forward compatibility, which is a large part
of why this format exists — so preservation had to be available, and it is: declare one field of
type `protobuf.Unknown`. It is not automatic because a message struct cannot grow a hidden field:
the sink must be a real field a caller can see, copy and reason about. The compile-time story is
symmetric — the sink must NOT appear in `pb_fields`, and every other field must.

Captured bytes are stored **verbatim** (tag included), not re-encoded from a parsed form. Verbatim
is what makes forwarding byte-exact for free, and it means a field this build cannot even name a
wire type for is still carried correctly. They are re-emitted after the known fields; field order
carries no meaning in protobuf, so that is lossless. The reference implementation judges this
end-to-end: `reference: a message proxied through a partial schema is unchanged` decodes a full
message through a two-field schema, re-encodes, and requires the reference to read back exactly
what it originally wrote.

`reject_unknown_fields` exists for the opposite posture — a receiver that must not forward what it
cannot validate.

### Groups (wire types 3/4) are not implemented

Deprecated and removed in proto3. They are *recognised* rather than ignored: `wire.Cursor.tag`
returns `error.UnsupportedWireType` for 3 and 4 by name, alongside the two unassigned wire types
(6, 7) that no conforming encoder emits. Silently skipping an unknown wire type would mean
guessing a length for bytes we cannot delimit.

### Two-pass encoding

A submessage is length-prefixed, so its length must be known before its first byte is written.
Upstream C++ solves this with `ByteSizeLong` + `SerializeWithCachedSizes`; the alternative —
serialising each submessage into a scratch buffer and prepending the length — costs an allocation
per nesting level and would make an allocation-free `encodeInto` impossible. `encodedSize` is
public because a gRPC framer needs exactly that number.

The failure mode of two passes is that they disagree. It is made loud: the buffer is sized from
pass one, every emitter write checks it fits, and pass two checks it filled the buffer
**exactly**, so any divergence aborts in the first test that runs rather than emitting a truncated
message. (Mutation M6 below confirms the check fires.)

The checks are real `@panic`s (`wire.size_mismatch_message`), not `std.debug.assert`s — audit F8,
2026-09-14. An assert does not exist in ReleaseFast/ReleaseSmall, where the same disagreement wrote
past the buffer and died with SIGSEGV. Measured cost of the per-write check, ReleaseFast, a
`Repeated` message with 1 024 varints and three strings, three runs of seven rounds each: best
round 8 207–8 260 ns/op before, 8 327–8 359 ns/op after — about 1–2 %, inside the run-to-run
spread (up to 6 % between runs).

## Threat model

Everything the decoder touches came from someone else. Three bounds are load-bearing.

### 1. A declared length is not evidence

The defect shape: *a length or count read from input, used to size an allocation or bound a loop,
before verifying the buffer holds that much.* A hostile 5-byte message can claim a 4 GiB
submessage.

The structural answer is that `wire.Cursor.take(n)` is the **only** way to consume a declared
length, and it compares `n` against the bytes really remaining before forming any slice. There is
no unchecked alternative to reach for at a call site. `n` is widened to `u64` before the
comparison so a 2^63 length cannot wrap on a 32-bit host, and the cursor's `pos <= buf.len`
invariant means `remaining()` never underflows.

A corollary worth stating explicitly: **no loop in the decoder is bounded by a number from the
input.** A packed repeated field's element count is bounded by a payload slice `take` already
proved present; a repeated field's element count is bounded by the message's own byte length.
There is no element-count field in this format to be lied to about, and none is synthesised.

Nothing is allocated before the check, so the failing path allocates zero bytes — asserted by
running these cases under `testing.allocator`.

Tested: a 4 GiB string claim, an oversized submessage length, an oversized packed payload, the
same lie inside an *unknown* field (the skip path must bound-check identically), and the
off-by-one boundary in both directions (a length one past the end fails; the exact length works).

### 2. Nesting depth is chosen by the attacker

Embedded messages recurse and the input decides how deep. `DecodeOptions.max_depth` (default 64;
protoc's own is 100) caps it. About three bytes of input buy one stack frame, so a 7 KiB message
is a 2000-deep recursive descent — the `hostile: the classic nesting bomb` test builds exactly
that and requires `error.DepthExceeded`. Removing the cap turns that test into a segfault (mutation
M7), which is the evidence that the cap is doing work rather than decorating the code.

The encoder is bounded by the same option for the same reason: a boxed self-recursive value built
at run time can be arbitrarily deep.

### 3. A duplicate field is a merge, not a replacement

The encoding spec has two rules for a field that appears more than once, and only one of them is
"last occurrence wins". Scalars, `string` and `bytes` are last-wins; an **embedded message** is
*merged* into the earlier occurrence (`MergeFrom`), recursively, with the submessage's own repeated
fields concatenating and its own scalars again last-wins.

Getting this wrong in the replacing direction is not a cosmetic divergence, it is a **field-hiding
primitive**: a sender appends a second, near-empty copy of a submessage and every field the first
copy set reverts to its type default in front of whatever authorisation or validation decision
reads the value — while a reference peer, and therefore any filter in front of us, still sees the
original field. No round trip can see this, because a canonical encoding never emits the shape;
only a foreign parser can settle it, which is why the case is in the interop corpus
(`conformance.zig`'s `semantic_cases`, replayed offline from the reference's own recorded verdict)
as well as in `adversarial.zig`.

It is implemented through the equivalence the spec itself states — parsing the concatenation of two
encodings equals parsing each and merging — so the *payload bytes* are gathered and decoded once
(`decode.zig`, `MergeBuf`). That matters for more than tidiness: decoding each occurrence and then
merging the values would have to re-copy every element of every already-decoded repeated field on
every further occurrence, and the sender picks the number of occurrences, so it is quadratic in the
input. Concatenation is linear, and the single-occurrence case — essentially all real traffic —
copies nothing, the payload staying a borrowed slice.

### 4. `string` means UTF-8, and the reference enforces it

proto3 requires a `string` field to carry valid UTF-8, and the reference implementation enforces it
**at parse time**: the Python runtime raises `UnicodeDecodeError` out of `ParseFromString`, naming
the field, so the whole message is refused (verified on both proto3 and proto2 descriptors). We
return `error.InvalidUtf8` for the same inputs — invalid start byte, overlong encoding, a UTF-16
surrogate half, a truncated sequence — all of which `std.unicode.utf8ValidateSlice` rejects and all
of which the reference rejects.

Accepting them would make this decoder the hole in a mixed fleet: a filter built on it passes a
message every reference peer refuses, and a consumer receives a `[]const u8` whose declared type
promises text. `bytes` is deliberately untouched — that is the kind for arbitrary octets, and the
reference accepts `0xff` there. **Asymmetry to know about:** the *encoder* does not validate, so a
caller who puts invalid UTF-8 into a `.string` field of a value it encodes will emit bytes the
reference rejects. The check is on the untrusted side, which is the side the threat model is about.

### 5. Declared length and nesting depth do not bound memory

Bullets 1 and 2 above stop a hostile *length* and a hostile *depth*. Neither stops a hostile
*shape*: rule 3's merge semantics require every occurrence of a singular/optional message field to
be concatenated before decoding (`decode.zig`'s `MergeBuf`), and that concatenation happens again at
every level a submessage is nested. A message with `k` parallel occurrences of the same field at
each of `d` levels needs wire bytes proportional to `k + d` but arena bytes proportional to `k * d`
— wave-3 audit finding `protobuf` F1 measured a *legal* 3.68 MiB message (comfortably under gRPC's
own 4 MiB default `max_recv_message_size`) driving the decode arena to 501.4 MiB, **136×**, and the
ratio scales with `max_depth`.

`DecodeOptions.max_arena_bytes` (default `default_max_arena_bytes`, 64 MiB) closes this the same way
`max_depth` closes rule 2: a hard total on bytes the decode arena may be granted, checked on every
allocation through a wrapping `CappedAllocator` (not just in `MergeBuf`, so it also covers the
smaller, non-merge amplification the audit measured — packed scalars and empty repeated
submessages/strings widening 20–55× just from Zig's in-memory representation being wider than the
wire form). Exceeding it surfaces as `error.OutOfMemory`, indistinguishable from a real allocator
exhaustion — deliberately: a caller that already handles OOM handles this. `grpc`, the one in-repo
consumer, does not leave this at the bare default: both `Stream.receive` (client) and
`Methods(..).Stream.receive` (server) set `.max_arena_bytes = frame.default_decode_arena_bytes` (8×
`max_recv_message_size`), so the memory bound tracks the wire bound it already advertises rather than
existing as a separate number an operator has to think about.

Honesty about precision: the cap bounds bytes *requested from the arena*, not the arena's own
backing allocation, which grows in geometrically-sized chunks and can therefore ask its parent
allocator for somewhat more than the logical total once a chunk boundary is crossed mid-request —
measured at roughly 1.5–1.6× in the reproduction above (a 64 MiB logical cap stopped an unbounded
attack at ~101 MiB of real backing memory, not exactly 64 MiB). That overhead is itself bounded (an
arena's growth strategy cannot compound the way unmerged nesting depth did before this fix), so the
result is still O(cap), not O(input) — the property that matters is that a small wire message can no
longer trade a small amount of attacker effort for an unbounded amount of memory.

### Smaller hardening

- **Varints are capped at 10 bytes**, and the 10th byte may only contribute the one bit that fits
  below 2^64. An over-large varint is **rejected** (`error.VarintOverflow`) rather than truncated
  the way upstream C++ does. Truncating lets one stream mean two different things to two readers,
  which is a parser-differential primitive; rejecting cannot, and the reference never emits such a
  varint, so nothing legitimate is lost.
- **Non-minimal varints are accepted** for a field's *value* — checked against the oracle
  (`18 81 00` → `ACCEPT n: 1`), so that one is parity, not a differential.
- **A non-minimally encoded *tag* is rejected** (`error.NonMinimalTag`), which is the opposite
  choice from the line above and deliberately so. The reference's pure-Python decoder dispatches
  on the tag's raw bytes (`_decoders_by_tag[tag_bytes]`), so a non-minimal tag never matches a
  known field there and is read as unknown — reading it by field number instead (this codec's old
  behaviour) let one byte string name two different fields to two readers, and for `proto3
  optional` a different *presence* verdict too (wave-3 audit finding `protobuf` F3, 32/32 tested
  variants disagreed with the reference). No conforming encoder, including this module's own,
  ever emits a non-minimal tag, so nothing legitimate is lost. ⚠ Honesty about scope: this was
  checked against the pure-Python reference only — `upb` (upstream C++) was not available to
  verify against, and reportedly dispatches by field number, which would agree with the old
  behaviour instead. If that turns out to matter for a specific peer, this is the line to revisit.
- **Field number 0** is reserved and rejected.
- **A wire-type mismatch is not a parse failure** — protobuf's rule is that such a field is
  unknown. It is skipped (and preserved, if there is a sink), matching the reference.
- **Exhaustive enums** return `error.InvalidEnumValue` on a value they cannot hold; non-exhaustive
  `enum(i32) { …, _ }` (the recommended, proto3-correct form) accepts anything.
- **`copy_strings = true` by default**, so a decoded value does not silently alias a buffer the
  caller is about to free. Zero-copy is available and documented as the caller taking on that
  lifetime.

Two sweeps back the above: decoding every prefix of a valid message, and a byte-flip sweep over
every offset x five patch values, both requiring a *typed error* and never a panic. In a Debug or
`ReleaseSafe` build that is also an assertion that no safety check trips (CONVENTIONS.md §7.1).

## Verification

Four layers, in increasing order of what they can prove.

1. **Round trip.** Necessary, and close to worthless alone. The strongest defects in this format
   are *consistent* between encoder and decoder and stay completely invisible to it.
2. **Golden bytes hand-derived from the spec** (`codec_test.zig`), including the canonical
   `08 96 01`, the ten-byte negative `int32`, zigzag vectors, little-endian fixed widths, and both
   packing forms.
3. **The live reference implementation** (`tools/interop.zig`, run by `zig build interop-protobuf`),
   which is the real anchor. The Python `protobuf` package is Google's own; descriptors are built
   at run time from `descriptor_pb2` + `descriptor_pool` + `message_factory`, so no `.proto` file
   and no `protoc` are involved. Its `tools/reference.py` `CASES` table and the Zig `wide_cases` /
   `repeated_cases` / `presence_cases` tables in `src/conformance.zig` mirror each other by name —
   that shared table is the entire marshalling protocol between the two processes. Three
   directions run:
   - our bytes vs the reference's bytes, **byte for byte** (proto3 field-number ordering makes
     these messages' encodings canonical, so equality is the right assertion, not "it parses");
   - the reference's bytes decoded by us, compared field by field through a comptime-generic
     structural comparison;
   - our bytes handed to the reference's *parser* in shapes the reference would never itself emit
     — packing flipped in both directions, and a message reassembled out of preserved unknown
     fields.

   Since 2026-09-06 this layer is a PROGRAM, not a test: it is never built by `test-protobuf` and
   never by `zig build`, so the module ships no foreign source and the suite needs no python3.
   Before that it was `src/reference_interop.zig`, a test that spawned `python3` and skipped when
   it was absent — which is every CI run, since nothing in this repository depends on a Python
   package at build time. A skip is not a failure, but it is also not an anchor: the mess was paid
   for and the evidence still might not be taken. It is now a pre-release check
   (`zig build interop-protobuf`), whose findings reach every machine through layer 4.
4. **Frozen reference bytes** (`golden_test.zig` + `testdata/golden_bytes.zig`, and
   `interop_replay_test.zig` + `testdata/interop_vectors.zig`), which closes that gap. The bytes in
   `golden_bytes.zig` are not hand-derived — they are `msg.SerializeToString(deterministic=True)`
   output that the Python `protobuf` package actually produced, captured by
   `zig build interop-protobuf -- --capture` and committed. `interop_vectors.zig` is the other half:
   the reference's own parse of each non-canonical input, re-serialized canonically, so the packing
   flip, the `MergeFrom` rule and `string`-field UTF-8 rejection are replayed from a foreign
   parser's verdict rather than re-checked against ourselves. Every
   case in layer 3's tables is checked against them, both directions, with no subprocess and no
   skip path: our encoder must reproduce the frozen bytes, and our decoder must recover the
   matching value from them. This is what layer 3 degrades to when python3 or the package is
   absent — the same external anchor, minus the ability to re-derive the bytes fresh each run. A
   comptime lookup (`@compileError` if a case has no frozen counterpart) and a count-canary test
   keep the two tables from silently drifting apart.

   Deliberately NOT frozen: the two tests in layer 3 that check whether the reference's *parser*
   accepts shapes it would never itself emit (packing flipped, a message reassembled from
   preserved unknown fields). Freezing those would only re-check our own decoder against itself —
   the whole point was a foreign judgment call. `codec_test.zig` covers the same shapes offline via
   independently hand-derived bytes instead.

### Mutation testing

Each mutation was applied to the implementation, the suite run, and the source restored. Every one
was caught; what matters is *by which layer*.

| # | Mutation | Caught by | Round trip alone? |
|---|---|---|---|
| M1 | zigzag transform dropped in **both** encoder and decoder | zigzag unit vectors, golden bytes, 3 reference tests | **NO — stayed green** |
| M2 | negative `int32` not sign-extended (naive `i32`→`u32`, 5 bytes not 10) | golden bytes, 2 reference tests, 2 frozen-golden tests (`golden_test.zig`, needs no python) | **NO — stayed green** (the reference decoder truncates to 32 bits, so even *their* parser reads the right value back; only the byte comparison sees it) |
| M3 | proto3 default packing turned off | schema derivation test, golden bytes, 2 reference tests | **NO — stayed green** |
| M4b | one specific **non-default** scalar value wrongly treated as the default and omitted | golden bytes, 2 reference tests | no |
| M5 | declared length allowed to overrun the buffer by one | off-by-one adversarial test; truncation sweep aborts | n/a |
| M6 | unknown fields captured but never re-emitted | the two-pass size/emit assertion fires (3 tests abort) | n/a |
| M6b | decoder never captures unknown fields | 3 unknown-field tests + the reference proxy test | n/a |
| M7 | decoder depth cap removed | depth test fails; the nesting bomb **segfaults** | n/a |
| M8 | decoder rejects the alternate packing form | "accepts both forms" test, repeated round trip, reference | partly |
| M9 | fixed-width fields written big-endian | golden bytes, 2 round trips, 3 reference tests | yes |

M1, M2 and M3 are the point of the table: three real, shipping-grade defects that a complete
self-round-trip suite passes with a clean conscience. Only an outside implementation sees them,
and for M2 only the *byte-level* comparison does — the reference's own decoder is happy with the
wrong bytes. That is the concrete argument for anchoring on bytes and not on values.

## Not implemented

- **`map<k, v>`.** Its wire form is a repeated submessage of `{key = 1, value = 2}`; a caller can
  express that today with a repeated message field and build the map itself. A first-class `map`
  kind would need an ordered-map value type and a merge rule for duplicate keys.
- **`oneof`.** Would map naturally onto a Zig tagged union; the encoder/decoder hooks are small,
  but the presence interaction with implicit-presence scalars needs its own test surface.
- **`Any`, well-known types, the canonical JSON mapping.** Each is a layer above the wire format.
- ~~A per-message size cache.~~ **Implemented 2026-09-15 for `encodeAlloc` (F6, A1/protobuf.md).**
  `encodeInto` (the allocation-free path — see encode.zig's module doc comment) is unchanged and
  still O(depth × fields): it has nowhere to put a cache without an allocator, and staying
  allocator-free is the entire reason this module has two encode entry points. `encodeAlloc` now
  builds a `SizeTree` — one node per submessage, in a throwaway arena over its own `gpa`, freed
  before the function returns — and the emit pass reads each submessage's size back from it
  instead of recomputing. Measured (ReleaseFast, `smp_allocator`, interleaved A/B, min of 25
  reps): a self-recursive chain 255 levels deep drops from 3.45ms to 118µs (29×); at the module's
  own `max_depth` default (64, also `grpc.Stream.sendInner`'s), 213µs → 31µs (6.9×). The cache
  is not free: for very shallow messages (depth 1–4, the common case for most schemas) the extra
  arena/allocation overhead makes `encodeAlloc` measurably SLOWER than before — depth 1: 818ns →
  950ns, depth 2: 1078ns → 1587ns, depth 4: 1860ns → 2481ns (reproduced across separate runs, not
  noise) — crossing over to a net win around depth 8. In absolute terms this is a few hundred
  nanoseconds against calls already in the low microseconds, and `encodeInto`'s hot path (used
  wherever the caller doesn't need `encodeAlloc`'s convenience) pays nothing at all, but it is a
  real, measured trade-off, not a pure win, and is recorded as one.
- **Streaming decode.** The API takes a complete buffer. gRPC frames arrive length-prefixed, so
  the framing layer above this one is the natural place for that.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** codec goldens hand-transcribed from spec; python-protobuf oracle skips if missing

**How it got there.** The anchoring work landed. DONE e080479: live python oracle frozen into committed goldens, survives CI
