# btcp2p

Pure-Zig **Bitcoin P2P wire-message codec**: the message envelope, the `version`/`verack`
handshake, the inventory/data-request messages, `tx`/`block` payload messages (reusing
`bitcointx`'s existing transaction codec), and connection housekeeping.

- This repo has a substantial Bitcoin/Lightning stack (`bitcointx`, `bitcoinscript`, `psbt`,
  `bech32`, `bip32`, `bip340`, `taproot`, `musig2`, plus the Lightning side) but, until now, no
  peer-to-peer network layer — `btcp2p` is that missing wire-format piece.
- **Platform:** any — every function is a pure transform over caller-owned byte slices/values, no
  I/O, no socket, no connection state.
- **Model after:** the Bitcoin Developer Reference / wiki protocol documentation
  (en.bitcoin.it/wiki/Protocol_documentation) for message shapes, Bitcoin Core's reference client
  (`src/net.h`, `src/chainparams.cpp`) for the constants actually deployed today (max message size,
  network magic bytes).

Provenance: the message shapes are clean-room from the public Bitcoin protocol
documentation (en.bitcoin.it/wiki/Protocol_documentation — a public
specification, see [`CONVENTIONS.md`](../../CONVENTIONS.md) §5), whose published
`verack`/`version` hex dumps are used as byte-exact test vectors. The constants
that are *deployed* rather than documented — `MAX_PROTOCOL_MESSAGE_LENGTH`
(`src/net.h`) and the network magic bytes (`src/chainparams.cpp`) — were read
from Bitcoin Core (**MIT**) as a **design reference**: values and behavior only,
no source ported.

## Scope: a codec, not a node

This repo does not build a validating Bitcoin node — a standing decision; wallet/signing code
talks to `bitcoind`/Electrum/Esplora over RPC, never reimplements consensus validation or a
mempool. `btcp2p` follows the same line for the P2P layer: it **parses wire bytes into typed
values and serializes typed values back into wire bytes**. It owns no chain state (no UTXO set, no
block index, no mempool), no peer manager (no address book, no ban scoring, no eviction), no
block/script validation (that's `bitcoinscript`'s and the caller's job), and no connection
lifecycle (no socket, no handshake sequencing, no reconnect/timeout policy). A caller supplies the
socket and the state machine; this module supplies "bytes in, typed message out" and back.

## Scope: messages implemented

See `SPEC.md` for the full design/threat-model writeup and exactly what's deferred/deprecated.

- **Envelope** (`envelope.zig`) — magic bytes for mainnet/testnet3/regtest/signet, the
  magic/command/length/checksum header, `decodeMessage`/`encodeMessage`.
- **Handshake** (`handshake.zig`) — `version` (with its two `net_addr` fields, nonce, user agent,
  start height, optional relay byte) and `verack` (zero-length payload).
- **Inventory/data** (`inventory.zig`) — `inv_vect` + the shared `inv`/`getdata`/`notfound` payload
  shape, `getblocks`/`getheaders` (also a shared shape), `headers`.
- **Payload messages** (`block.zig`) — `tx` (a direct re-export of `bitcointx.deserialize`/
  `bitcointx.serialize`, see below) and `block` (an 80-byte header, this module's own type, plus a
  transaction list decoded via `bitcointx.deserializePartial`).
- **Housekeeping** (`housekeeping.zig`) — `ping`/`pong` (modern BIP31 nonce form), `addr`/`getaddr`,
  `reject` (BIP61 — implemented, but flagged deprecated: disabled by Bitcoin Core since v0.18.0,
  removed entirely in v0.20.0).

Deliberately out of scope (not requested, or long-dead — SPEC.md has the full rationale): `addrv2`
(BIP155), `mempool`, `sendheaders`, `feefilter`, BIP152 compact blocks (`sendcmpct`/`cmpctblock`/
`getblocktxn`/`blocktxn`), BIP37 bloom filters (`filterload`/`filteradd`/`filterclear`/
`merkleblock`), the retired IP-Transactions messages (`checkorder`/`submitorder`/`reply`), and
`alert` (retired after a signature-forgery vulnerability; the signing key was burned — never
implement).

## Reusing `bitcointx`

`tx`/`block` are the two payload messages that carry consensus data, and this module does not
reimplement transaction parsing for either:

```zig
const btcp2p = @import("btcp2p");

// tx message: this IS bitcointx's wire format, no wrapper at all.
var tx = try btcp2p.decodeTx(allocator, tx_payload); // == bitcointx.deserialize
defer tx.deinit(allocator);

// block message: header (btcp2p's own type) + txns decoded via
// bitcointx.deserializePartial's documented back-to-back-decode contract.
var blk = try btcp2p.decodeBlock(allocator, block_payload);
defer blk.deinit(allocator);
std.debug.print("{d} txns, first value = {d}\n", .{ blk.txns.len, blk.txns[0].vout[0].value });
```

## Use

```zig
const btcp2p = @import("btcp2p");

// -- decode one message off a raw peer stream --
const decoded = try btcp2p.decodeMessage(stream_bytes, .mainnet);
if (std.mem.eql(u8, decoded.message.commandName(), "version")) {
    var v = try btcp2p.decodeVersion(decoded.message.payload);
    defer v.deinit(allocator);
    std.debug.print("peer user agent: {s}\n", .{v.user_agent});
}

// -- build and send a version message --
const my_version: btcp2p.Version = .{
    .version = 70016,
    .services = btcp2p.NODE_NETWORK,
    .timestamp = std.time.timestamp(),
    .addr_recv = .{ .services = 0, .ip = btcp2p.NetAddr.fromIpv4(.{ 1, 2, 3, 4 }), .port = 8333 },
    .addr_from = .{ .services = 0, .ip = @splat(0), .port = 0 },
    .nonce = my_random_nonce,
    .user_agent = "/zig-libs:0.1/",
    .start_height = my_best_height,
    .relay = true,
};
const payload = try btcp2p.serializeVersion(allocator, my_version);
defer allocator.free(payload);
const wire = try btcp2p.encodeMessage(allocator, .mainnet, "version", payload);
defer allocator.free(wire);
// write `wire` to the socket
```

## Verify

```
zig build test-btcp2p           # Debug
zig build test-btcp2p -Doptimize=ReleaseFast
zig fmt --check modules/btcp2p
```

Byte-exact against the Bitcoin wiki's own published hex dumps (protocol documentation page,
fetched directly): the `verack` message, the modern (protocol 60002) `version` message field-by-
field, the `addr`/`net_addr` worked examples — and against the real, published genesis-block raw
bytes (header + coinbase transaction, block hash reproduced from the header). See `SPEC.md` for
exactly what's externally anchored, what's in-house, and what's a labeled self round-trip.
