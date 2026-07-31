# lninvoice

Pure-Zig **Lightning payment requests**: BOLT#11 invoices (bech32-encoded, full decode+verify and
encode+sign) and BOLT#12 offers (bech32-*style* TLV, decode only — see `SPEC.md` for what's
deferred and why).

- The `lnwire` module's own doc comment already named this as future work: "BOLT#11 invoices /
  BOLT#12 offers (bech32-based — a future `lninvoice` module)". It reuses `bech32`'s charset + BCH
  checksum algorithm (reimplemented length-uncapped — BOLT#11 waives BIP173's 90-character
  ceiling), `k256.ecdsa_recover`'s RFC 6979 sign + public-key recovery for BOLT#11's recoverable
  signature (originally implemented in this module, moved to `k256` once it turned out to be
  general secp256k1 machinery — see `SPEC.md`), `lnwire`'s generic TLV stream parser (for BOLT#12's
  `offer`/`invoice_request`/`invoice` payloads), and `bip340`'s Schnorr sign/verify + tagged
  hashing (for BOLT#12's Merkle-tree signature).
- **Platform:** any — pure transform over caller-owned strings/bytes, no I/O. Allocator-based
  throughout (unlike `bech32`'s fixed-buffer codec: invoices are unbounded length and carry
  variable-length fields).
- **Model after:** BOLT#11 ("Invoice Protocol for Lightning Payments") + BOLT#12 ("Negotiation
  Protocol for Lightning Payments") — `lightning/bolts`, the public Lightning Network
  specification repository.

Provenance: clean-room from BOLT#11 and BOLT#12 (`lightning/bolts`), a public
specification whose own worked examples are the byte-exact anchors. No
third-party Lightning implementation was consulted, so no `NOTICE` entry is
required (root [`NOTICE`](../../NOTICE) §0).

## Scope

Implemented — see `SPEC.md` for the full design/threat-model writeup and exactly what's deferred:

- **BOLT#11 decode** (`decode`) — full tagged-field decode (`p`/`s`/`d`/`h`/`m`/`x`/`c`/`n`/`f`/
  `r`/`9`) + amount/network HRP parse + signature verification: recovers the payee's node ID from
  the signature when no `n` field is present, or verifies directly against `n` (requiring low-S)
  when it is. Fail-closed throughout.
- **BOLT#11 encode** (`encode`) — build + sign a payment request from a field list, either from a
  caller-supplied signature or a private key (RFC 6979 deterministic signing).
- **Recoverable ECDSA** (`ecdsa_recover.zig`, re-exported at root) — `sign`/`recoverPubkey`/
  `isLowS`, now implemented in `k256.ecdsa_recover`; this module just re-exports it, usable
  standalone either way.
- **BOLT#12 offer decode** (`decodeOffer`) — the `lno1...` checksum-less bech32-style TLV payload,
  every scalar `offer_*` field. `invoice_request`/`invoice` (BIP-340 Merkle-tree signing) are
  deferred — see `SPEC.md`.

## Use

```zig
const lninvoice = @import("lninvoice");

// -- decode + verify an untrusted invoice string --
var inv = try lninvoice.decode(allocator, invoice_str);
defer inv.deinit(allocator);

std.debug.print("payee node ID: {x}\n", .{inv.verified_pubkey});
switch (inv.verification) {
    .recovered => {}, // no `n` field -- verified_pubkey came from signature recovery
    .declared_node_id => {}, // `n` field present and verified against the signature
}
std.debug.print("amount_msat: {?d}\n", .{inv.amount_msat});
std.debug.print("payment_hash: {x}\n", .{inv.payment_hash});

// -- build + sign one (private-key path -- RFC 6979 deterministic) --
const fields = [_]lninvoice.TaggedFieldOut{
    .{ .payment_hash = payment_hash },
    .{ .payment_secret = payment_secret },
    .{ .description = "1 cup of coffee" },
};
const str = try lninvoice.encode(allocator, .{
    .network = .mainnet,
    .amount_msat = 250_000_000,
    .timestamp = @intCast(std.time.timestamp()),
    .fields = &fields,
}, .{ .private_key = my_privkey });
defer allocator.free(str);

// -- BOLT#12: decode an offer (parse only, unsigned) --
var offer = try lninvoice.decodeOffer(allocator, "lno1...");
defer offer.deinit(allocator);
std.debug.print("offer description: {?s}\n", .{offer.description});
```

## Verify

```
zig build test-lninvoice           # Debug
zig build test-lninvoice -Doptimize=ReleaseFast
zig fmt --check modules/lninvoice
```

Byte-exact against BOLT#11's own official worked examples (donation invoice + node-ID recovery,
amount/expiry/description vectors, route-hint decode, high-S handling, RFC 6979 re-derivation of
the spec's exact signature bytes) plus hostile/negative controls (bad checksum, unrecoverable
signature, sub-millisatoshi precision, missing required fields, high-S with a declared node ID)
— see `SPEC.md` for the full list and what each one checks.
