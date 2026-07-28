# btcp2p — spec

Design + threat notes for auditors. Usage: see ./README.md.

## Design & invariants

Pure codec, no I/O, no allocation beyond what the caller's `Allocator` provides (except
`envelope.zig`'s magic-byte lookups and `block_header.zig`'s `blockHash`, which touch no
allocator at all — fixed-size stack buffers). Eight files:

- `envelope.zig` — magic bytes for the four networks, the 24-byte header (magic + 12-byte
  NUL-padded command + little-endian length + double-SHA256 checksum), `decodeMessage`/
  `encodeMessage`. This is the untrusted-input boundary every other decoder in this module sits
  behind — see that file's module doc comment for the exact fail-closed check order (magic, then
  length-vs-ceiling, then length-vs-actual-remaining, then checksum).
- `message.zig` — a little-endian `Reader`/`Writer` (Bitcoin's wire format is little-endian
  throughout except `net_addr`'s `port` field, which is big-endian/"network byte order" per spec)
  plus CompactSize/`var_str` helpers built directly on `bitcointx.decodeCompactSize`/
  `encodeCompactSize` — Bitcoin's varint is one format shared by transactions, inventory lists, and
  address lists, and `bitcointx` already implements it byte-exact and fuzzed, so it is never
  redefined here.
- `net_addr.zig` — the `net_addr` peer-address structure, in both its no-timestamp (`version`
  message) and timestamp-prefixed (`addr` message, `TimedNetAddr`) forms, plus an IPv4-mapped-IPv6
  bridge (`ipv4()`/`fromIpv4`).
- `handshake.zig` — `version` + `verack`.
- `block_header.zig` — the 80-byte block header + `blockHash()` (double-SHA256 of the fixed
  80-byte serialization, matching `bitcointx.hash256.sha256d`'s use for `txid`/`wtxid`).
- `inventory.zig` — `inv_vect` (+ the shared `inv`/`getdata`/`notfound` payload shape), the shared
  `getblocks`/`getheaders` block-locator shape, and `headers`.
- `block.zig` — `tx`/`block`, reusing `bitcointx` directly (see "Reuse of `bitcointx`" below).
- `housekeeping.zig` — `ping`/`pong`, `addr`/`getaddr`, `reject`.

Concurrency: `.reentrant` — every function is a pure transform over caller-owned values, no
shared/global state.

## Reuse of `bitcointx` — what was reused vs. what had to be written

The task this module answers explicitly asked: check what `bitcointx` exposes and depend on it;
say if its shape isn't reusable rather than duplicating the parser. What `bitcointx` exposes at its
root (`Transaction`/`OutPoint`/`TxIn`/`TxOut`/`Witness`, `deserialize`/`deserializePartial`/
`serialize`/`serializeLegacy`/`serializeSegwit`, `encodeCompactSize`/`decodeCompactSize`/
`compactSizeLen`, and `hash256.sha256d`) turned out to be reusable **twice over**, not just once:

1. **The `tx` message payload IS `bitcointx`'s wire format, unchanged.** A `tx` message's payload
   is exactly one transaction in `bitcointx`'s legacy-or-BIP144-segwit wire form — `root.zig`
   re-exports `bitcointx.deserialize`/`bitcointx.serialize` directly as `decodeTx`/`serializeTx`,
   with zero new parsing code.
2. **The `block` message's transaction list rides `bitcointx.deserializePartial` exactly as its own
   doc comment anticipates.** That function's doc comment reads: "so a caller can decode several
   transactions packed back-to-back, e.g. from a `getdata`/block payload" — `block.zig`'s
   `decodeBlock` is that caller, looping `deserializePartial` over the remaining bytes and
   advancing by each call's reported `consumed` count. This also means `decodeBlock` inherits
   `bitcointx`'s own hostile-input safety property for free: a hostile huge `txn_count` can never
   force a large allocation, because the loop only appends a `Transaction` after
   `deserializePartial` has already fully, successfully parsed one (see `block.zig`'s module doc
   comment for the full argument).
3. **CompactSize itself.** Rather than redefining Bitcoin's varint a second time, every count field
   in this module (`inv`'s entry count, `addr`'s entry count, a `var_str`'s length, `getheaders`'s
   locator-hash count, ...) goes through `message.zig`'s `Reader.compactSize`/`Writer.putCompactSize`,
   which are thin wrappers over `bitcointx.decodeCompactSize`/`encodeCompactSize` — one
   byte-exact, fuzzed CompactSize implementation for the whole repo, not two.

What genuinely had to be written new (not duplicating anything `bitcointx` had): the envelope
(magic/command/length/checksum — outside `bitcointx`'s scope entirely, it operates on an
already-extracted payload), `net_addr`, the `version`/`verack` handshake, `inv_vect`/inventory
lists, the block-locator shape, and the 80-byte block header (`bitcointx` never had a block-header
type — its scope was always transaction (de)serialization + sighash, never blocks).

## Threat model / out of scope

`envelope.zig`'s `decodeMessage` is this module's untrusted-input boundary (see its own module doc
comment for the exact three-check order). Every other decoder in this module assumes its input
already passed that gate, but is independently fuzzed and hostile-input-tested anyway (defense in
depth — a caller could hand a decoder raw bytes directly, bypassing the envelope, e.g. when
decoding a PSBT-embedded or otherwise out-of-band transaction via `decodeTx`).

**Documented protocol maximums are enforced where the spec states one, not invented where it
doesn't:**

- `inv`/`getdata`/`notfound` — capped at 50,000 entries (the wiki's own stated maximum:
  "maximum 50,000 entries, which is just over 1.8 megabytes").
- `addr` — capped at 1000 entries (the wiki's own stated maximum: "Number of address entries
  (max: 1000)").
- `getblocks`/`getheaders`'s locator-hash count and `headers`'s entry count have **no documented
  hard maximum** in the spec, so none is invented here (CONVENTIONS.md's "model after a proven
  implementation", not "add a plausible-looking limit"). They still get the same remaining-bytes
  fail-fast bound described next.

**Every count-prefixed list, regardless of whether it has a documented maximum, is additionally
checked against `remaining_bytes / min_item_size` before its parse loop runs** — a hostile huge
count with too few bytes behind it is rejected outright (`error.TooManyItems`) rather than trusted
into an allocation. This is defense-in-depth on top of the real safety net (mirroring
`bitcointx.tx`'s own documented pattern): every parse loop in this module only grows its
`ArrayList` one successfully-parsed item at a time, so even without this check a hostile count could
never by itself force a large allocation — the first out-of-bounds item read fails closed with
`error.Truncated` first. The two real bugs this exact shape produced elsewhere in this repo this
week (an out-of-bounds write and a 4-byte input demanding a 29 TB allocation, both from a
length/count read off the wire and trusted before the buffer was known to hold it) are exactly what
both layers of this defense target.

**`envelope.zig`'s `MAX_PAYLOAD_LENGTH`** (4,000,000 bytes) is Bitcoin Core's own
`MAX_PROTOCOL_MESSAGE_LENGTH` (`src/net.h`, github.com/bitcoin/bitcoin) — checked against the
header's declared `length` *before* that length is ever used to slice `bytes`, independent of (and
prior to) the ordinary truncation check against `bytes.len`.

### What's deliberately not implemented, and why

- **`addrv2` (BIP155)** — a materially different, wider address format (variable-length network-ID
  + address, for Tor v3/I2P/CJDNS peers) layered over `addr`'s role. Genuinely new surface, not a
  small delta on `NetAddr`; deferred rather than half-built.
- **`mempool`, `sendheaders`, `feefilter`** — each trivially small (a bare command, or a single
  fixed-width field) but not in the task's requested message set; easy follow-ups if a consumer
  needs them.
- **BIP152 compact blocks** (`sendcmpct`/`cmpctblock`/`getblocktxn`/`blocktxn`) and **BIP37 bloom
  filters** (`filterload`/`filteradd`/`filterclear`/`merkleblock`) — each its own protocol
  extension with a nontrivial payload shape (differential encoding + short transaction IDs;
  serialized bloom-filter parameters), out of scope for this pass.
- **`checkorder`/`submitorder`/`reply`** — "This message was used for IP Transactions. As IP
  transactions have been deprecated, it is no longer used" (wiki, verbatim, for all three). Dead
  since before this module's scope was drawn; never implemented.
- **`alert`** — never implemented, and never will be: Bitcoin Core's alert system was retired after
  a signature-forgery weakness was found in its trust model, and the signing key was deliberately
  burned. There is no key left to verify an alert against, so a codec for it has nothing meaningful
  to check.
- **`reject` (BIP61)** — implemented (see `housekeeping.zig`), but flagged: Bitcoin Core deprecated
  it in v0.18.0, disabled it by default in v0.19, and removed it entirely in v0.20.0 (2020,
  github.com/bitcoin/bitcoin PR #15437) over the fingerprinting/bandwidth concerns BIP61 itself
  documents. No mainline peer on the network today sends this message. It's implemented anyway
  because the wire format is simple, well-specified, and some non-Core implementations or very old
  peers may still emit it — but a caller of this module should not expect one back from a modern
  Bitcoin Core node, and should not build handshake logic that waits on it.
- **Legacy pre-BIP31 `ping`** (zero-length payload, no `pong` reply at all) — predates every
  protocol version any peer on the network negotiates today; trivially representable as an empty
  byte slice if ever needed, so it isn't given its own type.

### Connection-lifecycle concerns explicitly NOT this module's job

(See README.md's "Scope: a codec, not a node" for the summary; this is the auditor-level detail.)
Stream resynchronization after a bad magic/checksum, handshake sequencing (send `version`, wait for
the peer's `version` and `verack` before accepting anything else — the wiki: "No further
communication is possible until both peers have exchanged their version"), protocol-version
negotiation (choosing the lower of the two peers' advertised versions and gating optional fields
like `relay` on it), ban scoring / misbehavior tracking, and retry/reconnect policy are all
caller-owned. This module's `decodeMessage`/`decode*` functions are pure transforms: give them
bytes, get a typed value or a typed error, with no memory of any previous call.

## Verification

- **Envelope** — `envelope.zig`'s tests decode the Bitcoin wiki's own published `verack` hex dump
  and the modern-(60002)-`version` hex dump's envelope (magic/command/length/checksum) byte-exact,
  both fetched directly from en.bitcoin.it/wiki/Protocol_documentation (not hand-transcribed from
  memory) — plus an in-house cross-check that `sha256d("")`'s first 4 bytes really do equal the
  wiki's published `verack` checksum, not just "this module agrees with itself".
- **`version`** — `handshake.zig`'s `decodeVersion` test reproduces the wiki's field-by-field
  breakdown of the same modern-(60002) example (`version`/`services`/`timestamp`/both `net_addr`
  fields/`nonce`/`user_agent`/`start_height`) byte-exact, then re-serializes and checks the result
  matches the original payload bytes exactly.
- **`net_addr`/`addr`** — `net_addr.zig` and `housekeeping.zig` reproduce the wiki's own
  "Hexdump example of Network address structure" and "Hexdump example of addr message" byte-exact.
- **`block_header`/`block`** — `block_header.zig` and `block.zig` decode the real, published
  genesis-block raw bytes (en.bitcoin.it/wiki/Genesis_block, "Raw block data", fetched directly)
  end to end: the 80-byte header, the CompactSize transaction count, and the one coinbase
  transaction (via `bitcointx.deserializePartial`) — then re-serialize and check the result matches
  the original raw bytes exactly, and independently reproduce the genesis block's well-known hash
  (`000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`, cross-checked live against
  blockstream.info's and mempool.space's `/api/block-height/0`) from the decoded header.
- **`inv`/`getdata`/`notfound`/`getblocks`/`getheaders`/`headers`/`reject`** — the wiki documents
  every field and (for `reject`) the CCode table, but publishes no standalone hex dump for these;
  their tests are labeled **in-house** (hand-built from the documented field layout, not an
  external byte-for-byte source) alongside encode→decode **self round-trips**. Every hostile-input
  test in this group is likewise in-house (there is no external "here is what a malformed `inv`
  looks like" vector to anchor to).
- **Fuzzing** — every `decode*` entry point in this module has a `std.testing.fuzz` harness
  (`envelope.decodeMessage`, `message.Reader.varBytes`/`compactSize`, `NetAddr.decode`,
  `handshake.decodeVersion`, `block_header.BlockHeader.decode`, `inventory.decodeInventoryList`/
  `decodeBlockLocator`/`decodeHeaders`, `block.decodeBlock`, `housekeeping.decodeAddr`/
  `decodeReject`) modeled on `modules/http/src/body.zig`'s shape and `bitcointx.tx`'s own harness:
  arbitrary bytes, with a length/count-shaped byte occasionally biased toward small values so the
  fail-fast-bound code paths get real traffic alongside fully random inputs. None found a crash or
  an unbounded allocation in this pass — the two-layer defense described above (documented maximum
  where one exists, remaining-bytes bound always, incremental-growth loop as the actual safety net)
  held.

Run: `zig build test-btcp2p` (Debug and `-Doptimize=ReleaseFast`).

## Status

`gap · any (pure codec, no I/O, no connection state) · codec · reentrant` + deps: `bitcointx` —
canonical source is `pub const meta` in src/root.zig.
