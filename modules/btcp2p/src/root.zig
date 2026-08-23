// SPDX-License-Identifier: MIT
//! btcp2p — the Bitcoin P2P wire-message codec: the message envelope
//! (magic/command/length/checksum), the `version`/`verack` handshake,
//! the inventory/data-request messages (`inv`/`getdata`/`notfound`/
//! `getblocks`/`getheaders`/`headers`), the two payload messages
//! (`tx`/`block`, reusing `bitcointx`'s existing transaction codec
//! rather than reimplementing it), and connection housekeeping
//! (`ping`/`pong`/`addr`/`getaddr`/`reject`). See SPEC.md for exactly
//! what's implemented, what's deliberately deferred, and where this
//! module's line is (parse/produce messages only -- see "Scope" below).
//!
//! ## Scope: a codec, not a node
//!
//! This repo does not build a validating Bitcoin node (a standing
//! decision -- wallet/signing code in this collection talks to
//! `bitcoind`/Electrum/Esplora over RPC, never reimplements consensus
//! validation or a mempool). `btcp2p` follows the same line for the P2P
//! layer: it parses wire bytes into typed values and serializes typed
//! values back into wire bytes. It owns **no**:
//!
//! - **chain state** -- no UTXO set, no block index, no mempool;
//! - **peer manager** -- no address book, no ban scoring, no eviction;
//! - **block/script validation** -- a `tx`/`block` message decodes into
//!   `bitcointx.Transaction` values with the same "opaque scriptSig/
//!   scriptPubKey bytes" contract `bitcointx` itself has; script
//!   execution is `bitcoinscript`'s job, consensus/PoW/difficulty
//!   checks are the caller's (or `bitcoind`'s);
//! - **connection lifecycle** -- no socket, no handshake *sequencing*
//!   (send `version`, wait for `verack` before anything else), no
//!   retry/reconnect/timeout policy, no protocol-version negotiation
//!   logic.
//!
//! A caller owns all of the above; this module's contract ends at "here
//! is a typed message" / "here are the bytes for this typed message".
//!
//! ## Layout
//!
//! - `envelope.zig` -- magic bytes (mainnet/testnet3/regtest/signet),
//!   the header (magic/command/length/checksum), `decodeMessage`/
//!   `encodeMessage` (the untrusted-input boundary every other decoder
//!   in this module sits behind -- see its module doc comment).
//! - `message.zig` -- shared little-endian `Reader`/`Writer` +
//!   CompactSize/`var_str` helpers built on `bitcointx`'s existing
//!   CompactSize codec.
//! - `net_addr.zig` -- the `net_addr` peer-address structure, in both
//!   its `version`-message (no timestamp) and `addr`-message (timestamp-
//!   prefixed) forms.
//! - `handshake.zig` -- `version` + `verack`.
//! - `block_header.zig` -- the 80-byte block header + `blockHash()`
//!   (genuinely new surface -- `bitcointx` has no block-header type).
//! - `inventory.zig` -- `inv_vect` + `inv`/`getdata`/`notfound` (one
//!   shared payload shape) + `getblocks`/`getheaders` (another shared
//!   shape) + `headers`.
//! - `block.zig` -- `tx`/`block`, reusing `bitcointx.deserialize`/
//!   `bitcointx.serialize` and `bitcointx.deserializePartial` directly
//!   (see that file's module doc comment for exactly how).
//! - `housekeeping.zig` -- `ping`/`pong`, `addr`/`getaddr`, `reject`
//!   (flagged deprecated -- see that file's module doc comment).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bitcoin P2P wire-message codec — envelope, version/verack handshake, inventory/data messages. Codec only: no chain state or validation.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure codec over caller-owned byte slices, no I/O, no peer/connection state
    .role = .codec,
    .concurrency = .reentrant, // no shared/global state; every call is over caller-owned values
    .model_after = "Bitcoin Developer Reference / wiki protocol documentation (en.bitcoin.it/wiki/Protocol_documentation); Bitcoin Core reference client for current-protocol constants (src/net.h's MAX_PROTOCOL_MESSAGE_LENGTH, src/chainparams.cpp's magic bytes) and BIP61's deprecation history",
    .deps = .{"bitcointx"},
};

pub const envelope = @import("envelope.zig");
pub const message = @import("message.zig");
pub const net_addr = @import("net_addr.zig");
pub const handshake = @import("handshake.zig");
pub const block_header = @import("block_header.zig");
pub const inventory = @import("inventory.zig");
pub const block = @import("block.zig");
pub const housekeeping = @import("housekeeping.zig");

// ── re-exports: envelope ─────────────────────────────────────────────────

pub const Network = envelope.Network;
pub const magic = envelope.magic;
pub const networkFromMagic = envelope.networkFromMagic;
pub const MAX_PAYLOAD_LENGTH = envelope.MAX_PAYLOAD_LENGTH;
pub const Message = envelope.Message;
pub const decodeMessage = envelope.decodeMessage;
pub const encodeMessage = envelope.encodeMessage;

// ── re-exports: addresses ────────────────────────────────────────────────

pub const NetAddr = net_addr.NetAddr;
pub const TimedNetAddr = net_addr.TimedNetAddr;

// ── re-exports: handshake ────────────────────────────────────────────────

pub const Version = handshake.Version;
pub const decodeVersion = handshake.decodeVersion;
pub const serializeVersion = handshake.serializeVersion;
pub const decodeVerack = handshake.decodeEmpty;
pub const NODE_NETWORK = handshake.NODE_NETWORK;
pub const NODE_GETUTXO = handshake.NODE_GETUTXO;
pub const NODE_BLOOM = handshake.NODE_BLOOM;
pub const NODE_WITNESS = handshake.NODE_WITNESS;
pub const NODE_COMPACT_FILTERS = handshake.NODE_COMPACT_FILTERS;
pub const NODE_NETWORK_LIMITED = handshake.NODE_NETWORK_LIMITED;

// ── re-exports: block header ─────────────────────────────────────────────

pub const BlockHeader = block_header.BlockHeader;

// ── re-exports: inventory / locator / headers ────────────────────────────

pub const InvVect = inventory.InvVect;
pub const knownInvName = inventory.knownName;
pub const INV_ERROR = inventory.INV_ERROR;
pub const INV_MSG_TX = inventory.INV_MSG_TX;
pub const INV_MSG_BLOCK = inventory.INV_MSG_BLOCK;
pub const INV_MSG_FILTERED_BLOCK = inventory.INV_MSG_FILTERED_BLOCK;
pub const INV_MSG_CMPCT_BLOCK = inventory.INV_MSG_CMPCT_BLOCK;
pub const INV_MSG_WITNESS_TX = inventory.INV_MSG_WITNESS_TX;
pub const INV_MSG_WITNESS_BLOCK = inventory.INV_MSG_WITNESS_BLOCK;
pub const INV_MSG_FILTERED_WITNESS_BLOCK = inventory.INV_MSG_FILTERED_WITNESS_BLOCK;

pub const Inv = inventory.Inv;
pub const decodeInv = inventory.decodeInv;
pub const serializeInv = inventory.serializeInv;
pub const GetData = inventory.GetData;
pub const decodeGetData = inventory.decodeGetData;
pub const serializeGetData = inventory.serializeGetData;
pub const NotFound = inventory.NotFound;
pub const decodeNotFound = inventory.decodeNotFound;
pub const serializeNotFound = inventory.serializeNotFound;

pub const BlockLocator = inventory.BlockLocator;
pub const GetBlocks = inventory.GetBlocks;
pub const decodeGetBlocks = inventory.decodeGetBlocks;
pub const serializeGetBlocks = inventory.serializeGetBlocks;
pub const GetHeaders = inventory.GetHeaders;
pub const decodeGetHeaders = inventory.decodeGetHeaders;
pub const serializeGetHeaders = inventory.serializeGetHeaders;

pub const HeaderEntry = inventory.HeaderEntry;
pub const Headers = inventory.Headers;
pub const decodeHeaders = inventory.decodeHeaders;
pub const serializeHeaders = inventory.serializeHeaders;

// ── re-exports: tx / block payload messages (bitcointx reuse) ────────────

const bitcointx = @import("bitcointx");
/// A `tx` message's payload IS `bitcointx`'s wire format (see
/// `block.zig`'s module doc comment) -- no wrapper needed.
pub const decodeTx = bitcointx.deserialize;
pub const serializeTx = bitcointx.serialize;
pub const Transaction = bitcointx.Transaction;

pub const Block = block.Block;
pub const decodeBlock = block.decodeBlock;
pub const serializeBlock = block.serializeBlock;

// ── re-exports: housekeeping ──────────────────────────────────────────────

pub const decodeGetAddr = handshake.decodeEmpty;
pub const Ping = housekeeping.Ping;
pub const Pong = housekeeping.Pong;
pub const decodePing = housekeeping.decodePing;
pub const serializePing = housekeeping.serializePing;
pub const decodePong = housekeeping.decodePong;
pub const serializePong = housekeeping.serializePong;
pub const Addr = housekeeping.Addr;
pub const decodeAddr = housekeeping.decodeAddr;
pub const serializeAddr = housekeeping.serializeAddr;
pub const MAX_ADDR_ENTRIES = housekeeping.MAX_ADDR_ENTRIES;
pub const RejectCode = housekeeping.RejectCode;
pub const Reject = housekeeping.Reject;
pub const decodeReject = housekeeping.decodeReject;
pub const serializeReject = housekeeping.serializeReject;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own -- every submodule must be named
// here too.
test {
    _ = envelope;
    _ = message;
    _ = net_addr;
    _ = handshake;
    _ = block_header;
    _ = inventory;
    _ = block;
    _ = housekeeping;
}

test "meta.deps names bitcointx" {
    try std.testing.expect(std.mem.eql(u8, meta.deps[0], "bitcointx"));
}

test "root re-exports resolve to the same functions as the submodules" {
    comptime std.debug.assert(decodeMessage == envelope.decodeMessage);
    comptime std.debug.assert(decodeVersion == handshake.decodeVersion);
    comptime std.debug.assert(decodeBlock == block.decodeBlock);
    comptime std.debug.assert(decodeTx == bitcointx.deserialize);
}
