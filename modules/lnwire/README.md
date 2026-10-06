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
  `commitment_signed`, `revoke_and_ack`, `update_fee`, `shutdown`, `closing_signed`,
  `update_fail_malformed_htlc` (refuses a `failure_code` without `BADONION`, both directions),
  `channel_reestablish` (with its `next_funding`/`my_current_funding_locked` TLVs typed and
  length-checked).
- **BOLT#7 gossip messages** — `channel_announcement`, `node_announcement`, `channel_update`,
  `announcement_signatures`, `query_short_channel_ids`/`reply_short_channel_ids_end`,
  `query_channel_range`/`reply_channel_range`, `gossip_timestamp_filter` (with `matches(timestamp)`),
  plus `channelAnnouncementDigest`/`nodeAnnouncementDigest`/`channelUpdateDigest`.
- **`node_announcement` address descriptors** — `addressIterator(msg.addresses)` yields typed
  `Address` values (`ipv4`/`ipv6`/`torv2`/`torv3`/`dns`) and stops at the first unknown type
  (`unparsed()` returns the rest); `encodeAddresses` builds the field and refuses port 0,
  non-ascending types, a second DNS name, and non-ASCII hostnames.
- **BOLT#9 feature bits** — `lnwire.features`: `isSet`, `supports` (either bit of a pair), `set`,
  `byteLenFor`, `firstUnknownEvenBit`, `minimal`.

Deliberately deferred (SPEC.md has the full rationale): BOLT#11 invoices / BOLT#12 offers
(bech32-based — the sibling `lninvoice` module), signature verification (caller's secp256k1 — see
"Use" below), onion routing (the sibling `sphinx` module), several BOLT#2/#7 messages outside this
module's required set (Interactive Transaction Construction, Channel Establishment v2, Splicing,
Quiescence, `start_batch`, modern closing), and per-field TLV-extension value semantics beyond the
raw `(type, value)` pair (except `channel_reestablish`'s two records).

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
// `verifyChannelAnnouncement` names the digest/signature/pubkey pairing so the
// caller only has to plug in `k256.verify` -- not re-derive which signature
// goes with which key from BOLT#7. A decoded-but-not-yet-called-verify*
// announcement is exactly as authenticated as any other unverified wire bytes.
fn myEcdsaVerify(_: ?*anyopaque, digest: [32]u8, sig: [64]u8, pubkey: [33]u8) bool {
    return k256.verify(pubkey, digest, sig); // your secp256k1
}
const verified = try lnwire.verifyChannelAnnouncement(gossip_bytes[2..], ann, myEcdsaVerify, null);

// -- reconnect: channel_reestablish --
var re = try lnwire.decodeChannelReestablish(allocator, reestablish_bytes);
defer re.deinit(allocator);
// error.InvalidTlvLength if next_funding / my_current_funding_locked is not 33 octets
if (re.nextFunding()) |nf| resendCommitmentSigned(nf.txid, nf.retransmit_flags & 1 != 0);
std.crypto.secureZero(u8, &re.your_last_per_commitment_secret); // caller-owned secret

// -- update_fail_malformed_htlc: error.BadOnionBitNotSet without the BADONION bit --
const mal = try lnwire.decodeUpdateFailMalformedHtlc(malformed_bytes);
_ = mal.failure_code & lnwire.BADONION; // always set here

// -- node_announcement addresses + features --
const node = try lnwire.decodeNodeAnnouncement(node_bytes);
var it = lnwire.addressIterator(node.addresses);
while (try it.next()) |addr| switch (addr) {
    .ipv4 => |a| connectTcp4(a.addr, a.port),
    .dns => |a| resolve(a.hostname, a.port),
    else => {},
};
if (lnwire.features.firstUnknownEvenBit(node.features, &.{ 0, 4, 6, 8, 12, 14, 16 })) |bit|
    std.debug.print("node requires unknown feature {d}\n", .{bit});

// -- subscribe to gossip --
const filt = try lnwire.serializeGossipTimestampFilter(allocator, .{
    .chain_hash = mainnet_genesis, .first_timestamp = now - 3600, .timestamp_range = 0xFFFF_FFFF,
});
defer allocator.free(filt);
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
round-trip-only gap for these three messages. (The sentence that followed here — "only the
BOLT#2 channel-management set remains round-trip-only" — was already false: SPEC's Anchoring
records all 13 BOLT#2 messages against rust-lightning's vectors.)

**Added 2026-10-06:** `channel_reestablish` (3 cases), `update_fail_malformed_htlc`,
`announcement_signatures`, `gossip_timestamp_filter` are byte-exact against rust-lightning's
`msgs.rs` encode tests in both directions, and the address-descriptor walker/encoder against the
10 vendored `node_announcement` cases — see `SPEC.md`'s "Added 2026-10-06" note.
