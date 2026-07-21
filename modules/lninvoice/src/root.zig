// SPDX-License-Identifier: MIT
//! lninvoice — Lightning payment requests: BOLT#11 invoices (full
//! decode+verify / encode+sign) and BOLT#12 offers (decode) + signed
//! `invoice_request`/`invoice` (parse/verify/build/sign via the BOLT#12
//! Merkle-tree BIP-340 signature — see `bolt12.zig`'s doc comment). Parses
//! untrusted strings throughout; every decode path is fail-closed — see
//! `SPEC.md` for the full threat-model writeup.
//!
//! This module is the bech32-based sibling `lnwire`'s own doc comment
//! already named as future work ("BOLT#11 invoices / BOLT#12 offers
//! (bech32-based — a future `lninvoice` module)"): it reuses `bech32`'s
//! charset + BCH-checksum algorithm (reimplemented length-uncapped, since
//! BOLT#11 waives BIP173's 90-character ceiling), `k256`'s field/group/
//! scalar arithmetic (adding the recoverable-ECDSA sign/recover BOLT#11
//! needs, which `k256` doesn't ship), `lnwire`'s generic TLV stream (for
//! BOLT#12's `offer`/`invoice_request`/`invoice` payloads), and `bip340`'s
//! Schnorr sign/verify + tagged hashing (for BOLT#12's Merkle-tree
//! signature).

const std = @import("std");

pub const bech32_raw = @import("bech32_raw.zig");
pub const bitpack = @import("bitpack.zig");
pub const ecdsa_recover = @import("ecdsa_recover.zig");
pub const bolt11 = @import("bolt11.zig");
pub const bolt12 = @import("bolt12.zig");

pub const meta = .{
    .platform = .any, // pure transform over caller-owned strings/bytes, no I/O
    .role = .codec,
    .concurrency = .reentrant, // no shared/global state
    .model_after = "BOLT#11 ('Invoice Protocol for Lightning Payments') + BOLT#12 ('Negotiation Protocol for Lightning Payments'), lightning/bolts",
    .deps = .{ "bech32", "k256", "lnwire", "bip340" },
};

// ── re-exports: BOLT#11 ──────────────────────────────────────────────────

pub const Network = bolt11.Network;
pub const RouteHop = bolt11.RouteHop;
pub const RouteHint = bolt11.RouteHint;
pub const Fallback = bolt11.Fallback;
pub const VerificationSource = bolt11.VerificationSource;
pub const Invoice = bolt11.Invoice;
pub const DecodeError = bolt11.DecodeError;
pub const decode = bolt11.decode;
pub const TaggedFieldOut = bolt11.TaggedFieldOut;
pub const EncodeParams = bolt11.EncodeParams;
pub const SignInput = bolt11.SignInput;
pub const encode = bolt11.encode;

// ── re-exports: recoverable ECDSA (also usable standalone) ──────────────

pub const Signature = ecdsa_recover.Signature;
pub const sign = ecdsa_recover.sign;
pub const recoverPubkey = ecdsa_recover.recoverPubkey;

// ── re-exports: BOLT#12 ──────────────────────────────────────────────────

pub const Offer = bolt12.Offer;
pub const decodeOffer = bolt12.decodeOffer;

// BOLT#12 "Signature Calculation" — the Merkle root + generic sign/verify.
pub const merkleRoot = bolt12.merkleRoot;
pub const signMerkle = bolt12.signMerkle;
pub const verifyMerkle = bolt12.verifyMerkle;
pub const invoice_request_sig_tag = bolt12.invoice_request_sig_tag;
pub const invoice_sig_tag = bolt12.invoice_sig_tag;

// BOLT#12 invoice_request (`lnr1...`) and invoice (`lni1...`).
pub const InvoiceRequest = bolt12.InvoiceRequest;
pub const decodeInvoiceRequest = bolt12.decodeInvoiceRequest;
pub const encodeSignedInvoiceRequest = bolt12.encodeSignedInvoiceRequest;
pub const Bolt12Invoice = bolt12.Invoice;
pub const decodeInvoice = bolt12.decodeInvoice;
pub const encodeSignedInvoice = bolt12.encodeSignedInvoice;

// Dark-tests aggregator (CONVENTIONS.md §6): a bare re-export does NOT pull
// a submodule's tests into the test binary on its own.
test {
    _ = bech32_raw;
    _ = bitpack;
    _ = ecdsa_recover;
    _ = bolt11;
    _ = bolt12;
}
