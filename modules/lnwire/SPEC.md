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
  relative to their caller's secp256k1).
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
"Scope" above); `channel_announcement`/`node_announcement`/`channel_update` and the whole BOLT#2
channel-management set remain round-trip-only (need a live daemon peer, `ANCHOR-TASKS.tsv`).

Run: `zig build test-lnwire` (Debug and `-Doptimize=ReleaseFast`).

## Status

`any (pure codec, no I/O) · codec · reentrant` + deps: none (std-only) — canonical source is
`pub const meta` in `src/root.zig`.
