// SPDX-License-Identifier: MIT

//! gate — the single switch that turns on the tests exercising HQC's
//! Part-2 decoder core: `reedmuller.zig`'s `RM(p).decodeSymbol` (fast
//! Hadamard transform, maximum-likelihood pick) and `reedsolomon.zig`'s
//! `RS(p).decode` (syndromes -> Berlekamp-Massey -> additive-FFT
//! root-finding -> Forney), composed by `code.zig`'s `Code(p).decode`.
//! Both are now REAL implementations (Fable pass, ports of the
//! reference's `reed_muller_decode` / `reed_solomon_decode` + `fft.c`) —
//! see those functions' doc comments for the algorithmic contract they
//! satisfy.
//!
//! Everything ELSE in Part 2 — `gf256.zig`'s field, `reedsolomon.zig`'s
//! `encode` (the systematic LFSR shift register), `reedmuller.zig`'s
//! `encodeBlock`/`encodeSymbol` (the fixed generator-matrix encode +
//! duplication), and `code.zig`'s `encode` (the RS-then-RM concatenation)
//! — is fully real today and needs no gate; together with their KAT tests
//! (byte-exact against the reference implementation, see
//! `kat_vectors_code.zig`) they are the proof this module's harness has
//! teeth independent of whether the decoder core is filled in yet, same
//! as `df-elect`'s `election.decide` / `pping`'s `matchEcho` gates
//! document for their own modules.
//!
//! Flipped to `true` now that BOTH `RM(p).decodeSymbol` and
//! `RS(p).decode` are real implementations. The gated tests in
//! `code_kat_test.zig` now actually drive round-trip `decode(encode(m))
//! == m` (zero-error and within-capacity-error cases) and the exhaustive
//! RM decode check against the real algorithms.
pub const decoder_core_implemented = true;
