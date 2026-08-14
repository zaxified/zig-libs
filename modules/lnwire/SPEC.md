# lnwire — spec

Design + threat notes for auditors. Usage: see ./README.md.

## Design & invariants

Pure codec, no I/O, no allocation beyond what the caller's `Allocator` provides (and the only
allocation any decode performs is a message's `Extension.records` array — see below). Six files:

- `tlv.zig` — BigSize (Lightning's varint: CompactSize with big-endian multi-byte forms) encode/
  decode, truncated-integer (`tu16`/`tu32`/`tu64`) encode/decode, and the generic BOLT#1
  `tlv_stream` parser (`parseStream`): strictly-increasing types, minimal `bigsize` encoding,
  length-vs-remaining-bytes bound, and the "it's ok to be odd" unknown-type rule (even unknown
  types fail the stream, odd unknown types are silently discarded). This file knows nothing about
  any *message's* per-type value encoding — that's the next layer up.
- `message.zig` — a bounds-checked big-endian `Reader`/`Writer`, the BOLT#1 "Fundamental Types"
  aliases (`Point`, `Signature`, `ChannelId`, ...), the 2-byte message-type frame (`openFrame`/
  `putFrameType`), and `Extension` — a message's trailing `tlv_stream`, decoded into its defined
  top-level record types via `tlv.parseStream`. Per-record *value* semantics (e.g. `fee_range`'s
  two `u64`s) are left to the caller — `Extension.find(type)` hands back raw bytes.
- `bolt1.zig` — `init`, `error`/`warning` (identical wire layout, one codec parameterized by
  `msg_type`), `ping`, `pong`.
- `bolt2.zig` — the 13 required BOLT#2 channel messages (see README's Scope section).
- `bolt7.zig` — the 7 required BOLT#7 gossip messages, plus `channelAnnouncementDigest`/
  `nodeAnnouncementDigest`/`channelUpdateDigest`: the double-SHA256 pre-image each message's
  signature(s) sign, computed exactly as BOLT#7 specifies ("beginning at offset 256/64, up to the
  end of the message" — the offset is precisely the byte-size of the signature field(s) each
  message leads with).
- `root.zig` — `meta` + a flat re-export of every public type/function, plus the dark-tests
  aggregator.

Concurrency: `.reentrant` — every `decode`/`serialize` function is a pure transform over
caller-owned bytes/values, no shared/global state.

## Ownership model

Zero-copy throughout, matching this repo's `bitcointx`/`stun`/`dnp3` convention: every
variable-length field a `decode*` function returns (`scriptpubkey`, `reason`, `features`,
`addresses`, TLV record values, ...) is a **borrowed** slice directly into the caller's input
buffer, never duplicated. This means the input buffer must outlive the decoded message. The only
heap allocation any decode performs is the `Extension.records` array itself (the small
`(type, value)`-pair array — not the value bytes each record borrows); `<Message>.deinit`
frees exactly that, nothing else. Messages with no defined `tlv_stream` (`funding_created`,
`funding_signed`, `revoke_and_ack`, `update_fee`, `shutdown`, `ping`, `pong`, `error`/`warning`,
`reply_short_channel_ids_end`) allocate nothing at all and their `deinit` is a no-op — but they
still generically parse (and correctly reject unknown-even / discard unknown-odd) any trailing
extension bytes, since BOLT#1's base wire format allows *any* message to carry one (see
`bolt1.zig`'s/`bolt2.zig`'s per-message `known_tlv_types` — empty for these).

`commitment_signed`'s `htlc_signatures` is the one field that reinterprets, rather than slices,
its input: `num_htlcs * 64` raw bytes are viewed as `[]align(1) const [64]u8` via
`std.mem.bytesAsSlice` — a pointer reinterpretation, not a copy (`[64]u8` has the same
layout/alignment as `u8`), so it stays zero-copy.

## Hostile-input handling

Every decode path returns a typed error, never panics, on truncated or adversarial bytes:

- A fixed-length field (a point, a signature, `update_add_htlc`'s 1366-byte
  `onion_routing_packet`, ...) or a `u16`-length-prefixed field (`shutdown`'s `scriptpubkey`,
  `update_fail_htlc`'s `reason`, ...) whose declared length exceeds the bytes actually remaining
  fails closed with `error.Truncated` *before* any read past the buffer — `message.Reader` compares
  the requested length against the remaining-bytes count as a `u64` before ever computing a slice
  index, so there is no overflow-then-OOB-read path even for a maximal `0xffff` length prefix.
- `commitment_signed`'s `num_htlcs` (up to 65535, i.e. up to ~4.19 MB of claimed signature bytes)
  is bounds-checked the same way — a hostile `num_htlcs` can't force an allocation or an
  out-of-bounds read; it just fails `error.Truncated` the moment the actual buffer doesn't have
  that many bytes (there is no allocation on this path at all — `htlc_signatures` is a
  reinterpreted borrow, see "Ownership model" above).
- Every trailing `tlv_stream` is `tlv.parseStream`'s own hostile-input handling: out-of-order or
  duplicate types (`error.NotStrictlyIncreasing`), non-minimally-encoded `bigsize` type/length
  (`error.NonMinimal`), a declared record length exceeding the bytes remaining
  (`error.Truncated`), and an unrecognized *even* top-level type (`error.UnknownEvenType`) — all
  typed, all fail-closed, matching BOLT#1's Type-Length-Value Format Requirements exactly.
- A message decoder handed the wrong 2-byte `type` (e.g. `decodeFundingSigned` given an
  `accept_channel` message) returns `error.WrongType` rather than misinterpreting the payload.

## Scope

**Implemented**, byte-exact against BOLT#1's own published test vectors where the spec provides
them (see "Verification" below):

- **BOLT#1 base wire**: BigSize (`tlv.encodeBigSize`/`decodeBigSize`), the generic `tlv_stream`
  (`tlv.parseStream`), the 2-byte message-type frame, `init`/`error`/`warning`/`ping`/`pong`.
- **BOLT#2 channel messages**: `open_channel`, `accept_channel`, `funding_created`,
  `funding_signed`, `channel_ready`, `update_add_htlc`, `update_fulfill_htlc`, `update_fail_htlc`,
  `commitment_signed`, `revoke_and_ack`, `update_fee`, `shutdown`, `closing_signed`.
- **BOLT#7 gossip messages**: `channel_announcement`, `node_announcement`, `channel_update`,
  `query_short_channel_ids`/`reply_short_channel_ids_end`, `query_channel_range`/
  `reply_channel_range`, plus the announcement/update signed-digest helpers.

**Deliberately deferred** (structurally noted, not half-built — each is a self-contained follow-on
unit of work, not a corner cut inside a message this module claims to implement):

- **BOLT#11 invoices / BOLT#12 offers** — bech32-based encodings, a distinct concern from
  BOLT#1-style binary TLV wire messages; a future `lninvoice` module.
- **Signature verification** — every `signature`/`bip340sig`/`point` field is opaque bytes; no
  secp256k1 anywhere in this module (a pure codec has no business owning curve arithmetic — the
  caller verifies `channelAnnouncementDigest(payload)` etc. against the message's signature
  field(s) and `node_id`/`bitcoin_key`, exactly the split `bitcointx`'s sighash functions use
  relative to their caller's secp256k1). `verifyChannelAnnouncement`/`verifyNodeAnnouncement`/
  `verifyChannelUpdate` (`bolt7.zig`) are the seam that does the pairing for the caller: each takes
  an `EcdsaVerifyFn` (a `(ctx, digest, signature, pubkey) -> bool` function pointer the caller
  supplies, the same function-pointer-seam shape `iec62351` uses for `RawVerifier`) and calls it
  once per signature with BOLT#7's own digest/signature/pubkey pairing already resolved — a
  `decodeChannelAnnouncement` result carries no signal of its own that it is unverified; calling
  `verify*` (or not) is what a caller's code shows.
- **Onion routing (BOLT#4)** — `update_add_htlc.onion_routing_packet` is an opaque 1366-byte
  array; encryption/decryption/Sphinx is the sibling `sphinx` module's job, not this codec's.
- **BOLT#2 messages not in the required set**: Interactive Transaction Construction (`tx_add_input`
  and siblings), Channel Establishment v2 (`open_channel2`/`accept_channel2`), Channel Splicing,
  Quiescence (`stfu`), `update_fail_malformed_htlc`, `start_batch`, the modern Closing Negotiation
  pair (`closing_complete`/`closing_sig` — this module implements only the legacy `closing_signed`
  negotiation), `channel_reestablish`.
- **BOLT#7 messages not in the required set**: `announcement_signatures`,
  `gossip_timestamp_filter`.
- **Per-field TLV value semantics beyond the raw `(type, value)` pair** — e.g. `channel_type`'s
  feature-bitmap interpretation, `fee_range`'s two-`u64` decode, `attribution_data`'s
  `20*u32 + 210*sha256[..4]` structure, `query_flags`'s per-`short_channel_id` bit array. Every
  message's trailing extension is generically parsed with the *correct* known-type set (so
  legitimate even-typed fields like `upfront_shutdown_script`/`blinded_path` round-trip correctly
  and genuinely-unknown even types are still rejected — see "Design & invariants" above), but the
  bytes of each known record are handed back raw. This mirrors the BOLT#7 digest split (expose the
  primitive, defer the domain-specific interpretation) applied one level further down.
- **Address-descriptor / script-form parsing** — `node_announcement.addresses` (the
  `ipv4`/`ipv6`/`torv3`/`dns` address-descriptor encoding) and `shutdown.scriptpubkey`'s
  `OP_0`/`OP_1`-`OP_16`/`OP_RETURN` allow-list are opaque byte slices, same "no Script/address
  interpretation" scope cut the sibling `bitcointx` module documents for `scriptSig`/
  `scriptPubKey`.

## Verification

`tlv.zig` is pinned byte-exact against BOLT#1's own **Appendix A: BigSize Test Vectors** (all 8
valid encode+decode cases, all 3 non-canonical-encoding cases, all 7 truncation cases) and
**Appendix B: Type-Length-Value Test Vectors** (every decoding-failure and decoding-success case
listed, transcribed via a test-local `hexBytes` helper directly from the spec's own hex strings —
including the vector needing 258 zero bytes to demonstrate "value truncated", cross-checked byte-
count-exact against the fetched spec text at authoring time — rather than hand-typed into `0x..`
array literals, eliminating transcription slip as a failure mode). The `n1`/`n2` namespaces are the
spec's own teaching example; `tlv.zig`'s test-local `n1Validate` mirrors exactly what a real
per-message typed-extension decoder (`bolt2.zig`'s/`bolt7.zig`'s `known_tlv_types` machinery, one
level up) would do.

Every BOLT#2/BOLT#7 message has a decode→serialize round-trip test (several also assert
re-serializing a *decoded* message reproduces the exact input bytes — a strong self-consistency
check beyond "decode doesn't crash"). `bolt7.zig`'s three digest helpers are each checked against
an independently-computed `sha256(sha256(payload[offset..]))` inline in the test (not the digest
function's own internals) — the digest for `channel_announcement` is further checked to be
**invariant** to changing signature bytes (excluded from the pre-image) and to **change** when a
byte after the signature block changes, directly exercising the "beginning at offset N" boundary
BOLT#7 specifies.

**Hostile input** — every message has at least one truncation/oversized-length-prefix test
asserting a typed error (never a panic, never unbounded work): a length prefix declaring more
bytes than remain (`shutdown.scriptpubkey`, `update_fail_htlc.reason`,
`reply_channel_range.encoded_short_ids`, `init.globalfeatures`, `ping.byteslen`,
`error.data`), a truncated fixed-width field (points, signatures, `commitment_signed`'s
4th-signature-cut-short case, `update_add_htlc`'s onion packet), `commitment_signed`'s `num_htlcs`
claiming ~4.19 MB more signature bytes than the buffer holds, and an unknown-even top-level TLV
type in several messages' extensions (`init`, `open_channel`, `query_channel_range`).

**BOLT#7 extended-query vectors (added 2026-08-02)** — `query_channel_range`, `reply_channel_range`,
and `query_short_channel_ids` are each additionally checked against `lightning/bolts`' own
`bolt07/extended-queries.json` (10 rows, CC-BY 4.0 — see `modules/lnwire/NOTICE`), vendored as
`src/bolt7_extended_queries_kat_vectors.zig`. Both directions are driven: DECODE parses the
official `hex` and asserts `chain_hash`/block-range/`complete` fields, the raw `encoded_short_ids`
opaque blob, and (independently reconstructed from the vector's own decoded fields, not just
self-consistency) `timestamps_tlv`/`checksums_tlv` content wherever this module's codec actually
interprets it; ENCODE builds a message from the vector's decoded fields and asserts the result is
byte-exact against the official `hex` — the direction this pass prioritized, since the pre-existing
suite only round-tripped through this module's own encoder/decoder pair. 4 of the 10 rows use the
`COMPRESSED_ZLIB` short_channel_id (and, in two of those, also `query_flags`/`timestamps_tlv`)
encoding; this module has no zlib codec (see "Scope" above) and never interprets `query_flags`'
per-scid bit-array content regardless of its own encoding, so those rows' compressed *content* is
not reconstructed from the vector's semantic fields — the encoding-type byte itself, every
non-compressed field, and a byte-exact decode→re-encode round trip of the opaque blob are still
checked. `checksums_tlv` has no encoding byte in BOLT#7 (always raw), so it is independently
checked even in an otherwise-`COMPRESSED_ZLIB` row. `announcement_signatures` and
`gossip_timestamp_filter` remain unanchored (deferred, not in this module's implemented set — see
"Scope" above).

**BOLT#7 announcement/update vectors (added 2026-08-02)** — `channel_announcement`,
`node_announcement`, and `channel_update` are each additionally checked against
`lightningdevkit/rust-lightning`'s own encode/decode test hex (`lightning/src/ln/msgs.rs`'s
`encoding_channel_announcement`/`encoding_node_announcement`/`encoding_channel_update` tests, dual
MIT/Apache-2.0 — see `modules/lnwire/NOTICE`), vendored as
`src/bolt7_announcement_update_kat_vectors.zig`: 22 vectors total (4/10/8 respectively), every
parameter combination the upstream tests drive, none synthesized. `lightning/bolts` (BOLT#7's own
spec repository) carries no test vectors for these three messages, so this is an independent
implementation's frozen encoder output rather than the spec authors' own data — the vendored file's
module doc comment records exactly which upstream test/commit and why that is still a real anchor
(only hex output taken, never their encoder/decoder read for its own sake). Both directions are
driven: DECODE parses the official bytes and asserts every field, including `channel_announcement`'s
4-signature order (`node_signature_1`, `node_signature_2`, `bitcoin_signature_1`,
`bitcoin_signature_2`) and the excess/trailing-data bytes BOLT#7 requires be preserved verbatim;
ENCODE builds the message from those same fields and asserts byte-exact output against the official
bytes — the direction this pass prioritized, since the pre-existing suite only round-tripped through
this module's own encoder/decoder pair. All 22 vectors are usable in both directions (unlike 4 of the
extended-query rows above): `node_announcement.addresses` (ipv4/ipv6/torv2/torv3/hostname) and
`channel_announcement.features` (including an unknown-bits case) are opaque byte slices in this
module regardless of what they encode, so no vector needed skipping for an unimplemented encoding.
`channel_update.htlc_maximum_msat` is unconditional in BOLT#7's current spec text (the
`option_channel_htlc_max` feature that used to gate it is now mandatory), matching every vector.

This closes the "round-trip only" gap previously recorded here for these three messages; the whole
BOLT#2 channel-management set remains round-trip-only (needs a live daemon peer, the anchor record in `SPEC.md`).

Run: `zig build test-lnwire` (Debug and `-Doptimize=ReleaseFast`).

## Status

`any (pure codec, no I/O) · codec · reentrant` + deps: none (std-only) — canonical source is
`pub const meta` in `src/root.zig`.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** BigSize/TLV base wire + BOLT#7 announcements/queries + all BOLT#2 messages vs bolts + rust-lightning msgs.rs, byte-exact

**How it got there.** The anchoring work landed. DONE: BOLT#1 base wire; BOLT#7 extended queries (447b970) + announcements/updates (6ffc927); BOLT#2 channel management - all 13 implemented messages, every upstream parameter combination, byte-exact both directions. No regtest daemon was needed: rust-lightning's msgs.rs encode tests carry the wire hex and are dual MIT/Apache-2.0. Deferred by SPEC (splicing, announcement_signatures, gossip_timestamp_filter) is not debt. Only zlib-compressed extended-query payloads stay decode-only (no zlib here). CLOSED 2026-08-08 (wave-2 F2): "BOLT#1 App A/B" above covers only the BigSize/TLV *primitives*, not the *message* layer built on them — `init`/`error`/`warning`/`ping`/`pong` had 0 external vectors, self round-trip + hostile-truncation only, until this pass. Imported rust-lightning's `encoding_init`/`encoding_error`/`encoding_warning`/`encoding_ping`/`encoding_pong` (`bolt1_kat_vectors.zig`, `bolt1_kat_test.zig`), byte-exact-verified against the fetched `msgs.rs` programmatically before transcribing. `error`/`warning` share one vendored vector (BOLT#1 defines them with one layout; upstream's own two tests drive identical bytes). CLOSED 2026-08-08 (wave-2 F3): the announcement/update *digests* `channelAnnouncementDigest`/`nodeAnnouncementDigest`/`channelUpdateDigest` compute over — the actual security-relevant output fed to secp256k1 verify — were pinned only by literal offset recomputation inside this module's own tests (`payload[256..]`/`[64..]`, hand-derived from the same BOLT#7 reading as production, so a *consistently* wrong offset would agree with itself and stay green forever). Added one independently-recomputed digest per message (Python `hashlib.sha256`, twice, over the tail of an already-vendored rust-lightning `payload_hex` vector — no new upstream source, since rust-lightning's own tests don't assert digest values, only wire bytes). Mutation-tested the exact failure mode this closes: co-mutated the production offset (256→255) AND the old self-referential test's hardcoded literal (same change, simulating a consistently-wrong-from-the-start reading) — old test stayed green, new test alone caught it (`exit 1, 1/90 fail`); both reverted.
