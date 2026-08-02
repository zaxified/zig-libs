# lnwire

Pure-Zig **Lightning Network wire-message codec**: BOLT#1's BigSize varint + generic TLV stream,
the core BOLT#2 channel-management messages, and the BOLT#7 gossip messages (plus the
double-SHA256 digest each gossip message's signature(s) sign).

- No mature pure-Zig Lightning message-layer library exists; this is the wire-format complement to
  the repo's existing `bolt8` (BOLT#8 `Noise_XK` transport — the encrypted pipe this module's
  messages ride over), `sphinx` (BOLT#4 onion routing), `bip340`/`k256` (the signature primitives
  this module's fields carry but never verifies itself).
- **Platform:** any — every function is a pure transform over caller-owned byte slices/values, no
  I/O, no allocation beyond the caller's `Allocator` (and only for a message's small TLV-record
  array — see `SPEC.md`'s "Ownership model").
- **Model after:** BOLT#1 ("Base Protocol"), BOLT#2 ("Peer Protocol for Channel Management"), BOLT#7
  ("P2P Node and Channel Discovery") — `lightning/bolts`, the public Lightning Network
  specification repository.

Provenance: clean-room from BOLT#1/#2/#7 (`lightning/bolts`), a public
specification; the TLV/BigSize codec is pinned byte-exact against the spec's own
Appendix A and B vectors. No third-party Lightning implementation was consulted,
so no `NOTICE` entry is required for the CODE (root [`NOTICE`](../../NOTICE) §0).

**Added 2026-08-02:** that disclaimer covers the CODE, which remains
clean-room. The module now separately vendors `lightning/bolts`' own BOLT#7
test-vector DATA (`bolt07/extended-queries.json`, CC-BY 4.0), which does
require attribution — see [`NOTICE`](./NOTICE), a module-local file per root
NOTICE §1's policy.

## Scope

Implemented — see `SPEC.md` for the full design/threat-model writeup and exactly what's deferred:

- **BigSize** (`decodeBigSize`/`encodeBigSize`) — Lightning's varint (CompactSize with big-endian
  multi-byte forms), fail-closed on truncation and non-minimal encodings.
- **Truncated integers** (`tlv.decodeTruncated`/`encodeTruncated`) — the `tu16`/`tu32`/`tu64`
  convention (0..N bytes, no leading zero).
- **The generic `tlv_stream`** (`parseTlvStream`) — strictly-increasing types, minimal `bigsize`
  encoding, length-vs-remaining bound, "it's ok to be odd" (even unknown types fail the stream, odd
  unknown types are silently discarded).
- **BOLT#1 setup/control messages** — `init`, `error`/`warning`, `ping`, `pong`.
- **BOLT#2 channel messages** — `open_channel`, `accept_channel`, `funding_created`,
  `funding_signed`, `channel_ready`, `update_add_htlc`, `update_fulfill_htlc`, `update_fail_htlc`,
  `commitment_signed`, `revoke_and_ack`, `update_fee`, `shutdown`, `closing_signed`.
- **BOLT#7 gossip messages** — `channel_announcement`, `node_announcement`, `channel_update`,
  `query_short_channel_ids`/`reply_short_channel_ids_end`, `query_channel_range`/
  `reply_channel_range`, plus `channelAnnouncementDigest`/`nodeAnnouncementDigest`/
  `channelUpdateDigest`.

Deliberately deferred (SPEC.md has the full rationale): BOLT#11 invoices / BOLT#12 offers
(bech32-based — a future `lninvoice` module), signature verification (caller's secp256k1 — see
"Use" below), onion routing (the sibling `sphinx` module), several BOLT#2/#7 messages outside this
module's required set (Interactive Transaction Construction, Channel Establishment v2, Splicing,
Quiescence, `announcement_signatures`, ...), and per-field TLV-extension value semantics beyond the
raw `(type, value)` pair.

## Use

```zig
const lnwire = @import("lnwire");

// -- decode a message received over an already-decrypted BOLT#8 transport --
var msg = try lnwire.decodeOpenChannel(allocator, received_bytes);
defer msg.deinit(allocator); // frees only the Extension.records array -- received_bytes must
                              // outlive `msg` (var-length/TLV fields borrow it, see SPEC.md)

std.debug.print("funding_satoshis = {d}\n", .{msg.funding_satoshis});
const channel_type = msg.extension.find(1); // raw bytes of the channel_type TLV, if present

// -- build and serialize one back --
const reply: lnwire.AcceptChannel = .{
    .temporary_channel_id = msg.temporary_channel_id,
    // ... fill in the rest ...
};
const wire_bytes = try lnwire.serializeAcceptChannel(allocator, reply);
defer allocator.free(wire_bytes); // hand this to bolt8.Transport for encryption + framing

// -- BOLT#7 gossip: verify a channel_announcement's signatures (caller's secp256k1) --
const ann = try lnwire.decodeChannelAnnouncement(gossip_bytes);
const digest = try lnwire.channelAnnouncementDigest(gossip_bytes[2..]); // payload, post 2-byte type
// caller: k256.verify(ann.node_id_1, digest, ann.node_signature_1) and 3 more checks
```

## Verify

```
zig build test-lnwire           # Debug
zig build test-lnwire -Doptimize=ReleaseFast
zig fmt --check modules/lnwire
```

Byte-exact against: BOLT#1 Appendix A's BigSize test vectors (all encode/decode/failure cases) and
Appendix B's TLV stream test vectors (every decoding-success and decoding-failure case, including
the ordering/duplicate-type and value-truncation vectors) — see `SPEC.md` for exactly what was
verified against what, plus every message's decode→serialize round-trip and the announcement-digest
offset-boundary checks.

**Added 2026-08-02:** `query_channel_range`/`reply_channel_range`/`query_short_channel_ids` are
additionally byte-exact against `lightning/bolts`' own `bolt07/extended-queries.json` vectors (10
rows, both DECODE and ENCODE directions) — see `SPEC.md`'s "BOLT#7 extended-query vectors" note
and `modules/lnwire/NOTICE` for the required CC-BY 4.0 attribution. 4 of the 10 rows exercise the
`COMPRESSED_ZLIB` short_channel_id/`query_flags` encoding this module does not implement; those
rows' compressed content is not independently reconstructed (documented per-row in `bolt7.zig`'s
tests), only the fields this module's codec actually interprets.

**Also added 2026-08-02:** `channel_announcement`/`node_announcement`/`channel_update` are
additionally byte-exact against `lightningdevkit/rust-lightning`'s own encode/decode test hex (22
vectors, both DECODE and ENCODE directions, dual MIT/Apache-2.0) — `lightning/bolts` carries no
vectors of its own for these three messages. See `SPEC.md`'s "BOLT#7 announcement/update vectors"
note and `modules/lnwire/NOTICE` for the required attribution. This closes the previous
round-trip-only gap for these three messages; only the BOLT#2 channel-management set remains
round-trip-only.
