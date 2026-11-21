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

That disclaimer covers the CODE, which remains
clean-room. The module separately vendors `lightning/bolts`' own BOLT#7
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
- **Typed TLV records** — accessors with decode- and encode-time length checks for the known records of `init`, `open_channel`/`accept_channel`, `closing_signed`, `update_fulfill_htlc`/`update_fail_htlc`, `query_short_channel_ids`, `query_channel_range` and `channel_reestablish`; the raw `Extension` (`find(type)`) stays the lossless form (SPEC *Typed TLV records*).
- **Newer BOLT#2 messages** (`bolt2_v2`) — `stfu`, `open_channel2`/`accept_channel2`, the interactive-tx messages, splicing, `closing_complete`/`closing_sig`, `start_batch`; **zlib-compressed lists** are read (`decodeShortIds`, `decodeTimestampPairs`, `QueryFlags.decode`).
- **BOLT#9 feature bits** — `lnwire.features`: `isSet`, `supports` (either bit of a pair), `set`,
  `byteLenFor`, `firstUnknownEvenBit`, `minimal`; every row of BOLT#9's table named: `Feature`, `table`, `row`,
  `setFeature`, `hasFeature`, `checkDependencies` (set feature whose dependency is missing).

## Not provided

No BOLT#11 invoices / BOLT#12 offers (the sibling `lninvoice`), no signature verification (the caller's secp256k1 plugs in through `verifyChannelAnnouncement` and its siblings, see "Use"), no onion routing (the sibling `sphinx`), no interpretation of TLV values beyond the typed accessors, and not yet the BOLT#2 interactive-tx / v2 channel establishment / splicing / quiescence / `start_batch` / modern closing messages or zlib-compressed range queries. The reasons are in SPEC *What is deliberately not done*; the open items in *Backlog / deferred*.

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
the ordering/duplicate-type and value-truncation vectors); `query_channel_range`/`reply_channel_range`/
`query_short_channel_ids` against `lightning/bolts`' own `bolt07/extended-queries.json` (10 rows, both
DECODE and ENCODE directions; the 4 `COMPRESSED_ZLIB` rows are decoded and compared with the arrays the file states, `bolt7_zlib_test.zig`); the BOLT#1 and BOLT#2 messages, the three
BOLT#7 announcement/update messages (22 vectors), `channel_reestablish`, `update_fail_malformed_htlc`,
`announcement_signatures`, `gossip_timestamp_filter` and the address-descriptor walker/encoder against
`lightningdevkit/rust-lightning`'s encode/decode test hex (dual MIT/Apache-2.0; `lightning/bolts` carries no
vectors of its own for these). See `SPEC.md` *Verification* for exactly what was checked against what, and
`modules/lnwire/NOTICE` for the required attribution.
