# oscore

OSCORE (Object Security for Constrained RESTful Environments, RFC 8613):
end-to-end application-layer security for CoAP, built on a COSE_Encrypt0
wrapper around an AEAD. This module targets the MANDATORY-to-implement
ciphersuite only — **AES-CCM-16-64-128** (COSE algorithm 10: 128-bit key,
13-byte nonce, 64-bit/8-byte tag) for the AEAD, and **HKDF-SHA-256** for
§3.2.1 context derivation. `std.crypto.aead.aes_ccm.Aes128Ccm8` is exactly
this AEAD; `std.crypto.kdf.hkdf.HkdfSha256` is exactly this KDF — neither
is a gap. The OSCORE-specific construction around them (security context,
nonce, AAD, compressed wire option, replay protection) is this module.

**Status: complete.** The §3.2.1 `info` CBOR encoder (`encodeInfo`), the
§5.4 `aad_array`/`Enc_structure` CBOR encoders (`encodeAadArray`,
`encodeEncStructure`), the §6.1 compressed COSE option codec
(`OscoreOption`), the §3.2.2 anti-replay sliding window (`ReplayWindow`),
and the six crypto cores (`deriveKey`, `deriveContext`, `computeNonce`,
`buildAad`, `protect`, `unprotect`) are all implemented and KAT-validated
— no `@panic`/TODO stub remains in `root.zig`. See [SPEC.md](SPEC.md) for
the design and the nonce/AAD byte layouts.

**CoAP-agnostic by design**: this module has no build dependency on the
sibling `coap` module and never parses or builds a CoAP message itself —
`protect`/`unprotect` operate on the RFC 8613 §5.3 plaintext and §5.4
options as opaque caller-supplied bytes. The intended integration is
`coap` (RFC 7252 message codec, already in this repository) assembling
those bytes and calling into `oscore` as its object-security layer.

| File | Contents |
|---|---|
| `root.zig` | Security context types (`SecurityContext`, `CommonContext`, `SenderContext`, `RecipientContext`); `ReplayWindow`; the CBOR/option codecs (`encodeInfo`, `encodeAadArray`, `encodeEncStructure`, `OscoreOption`); the 6 crypto cores (`deriveKey`, `deriveContext`, `computeNonce`, `buildAad`, `protect`, `unprotect`) — all REAL |
| `kat_vectors.zig` | RFC 8613 Appendix C's official test vectors — all six C.1-C.3 key-derivation vectors (client + server) and all five C.4-C.8 protected-message vectors |
| `kat_test.zig` | Byte-exact KAT assertions against every Appendix C field, plus tamper-rejection, replay-rejection, and an end-to-end round-trip test |

## Import

```zig
const oscore = @import("oscore");
```

## Usage

```zig
// Derive a full security context from the small set of RFC 8613 §3.2
// input parameters.
var client_ctx = try oscore.deriveContext(
    allocator, master_secret, master_salt, id_context,
    sender_id, recipient_id, .aes_ccm_16_64_128,
);

// Protect an outgoing message (the caller assembles `plaintext` per
// §5.3 — CoAP Code + Class E options + payload marker + payload; the
// sibling `coap` module's job, not this one's).
var piv_buf: [oscore.OscoreOption.max_partial_iv_bytes]u8 = undefined;
const protected = try oscore.protect(allocator, &client_ctx, plaintext, .{
    .request_kid = client_ctx.sender.id,
    // AadParams.request_piv must carry the SAME minimal-length encoding
    // `OscoreOption.encode` uses on the wire (§5.4/§6.1) — this message
    // IS the request, so it is this call's own about-to-be-consumed
    // sequence number, encoded via the same helper `encode` uses.
    .request_piv = oscore.OscoreOption.encodePartialIv(client_ctx.sender.sequence_number, &piv_buf),
}, true, null);
// protected.option  -> encode via OscoreOption.encode for the CoAP OSCORE option
// protected.ciphertext -> the CoAP payload

// Unprotect an incoming message on the peer side.
const plaintext = try oscore.unprotect(
    allocator, &server_ctx, decoded_option, ciphertext, aad_params,
    request_nonce_source, is_request,
);
defer allocator.free(plaintext);
```

`OscoreOption.encode`/`.decode` handle the §6.1 compressed
COSE option wire format directly:

```zig
const opt = oscore.OscoreOption{ .partial_iv = 20, .kid = sender_id };
const wire = try opt.encode(allocator); // -> CoAP OSCORE option value bytes
const decoded = try oscore.OscoreOption.decode(wire);
```

`ReplayWindow` is a standalone sliding anti-replay bitmap, usable on its
own:

```zig
var rw = oscore.ReplayWindow{};
if (rw.check(seq)) {
    // ... verify the AEAD tag for `seq` ...
    rw.update(seq); // ONLY after successful verification — see ReplayWindow's doc comment
}
```

### Surviving a restart (RFC 8613 §7.5 / Appendix B.1)

`sender.sequence_number` and `recipient.replay_window` are RAM state.
Re-deriving the same context after a reboot restarts the nonce sequence
at 0 (a two-time pad against every message already sent) and forgets
every request already accepted (every captured request replays). A
context that outlives the process needs the caller to persist and resume
that state — the module supplies the arithmetic, the caller the storage:

```zig
// Sending side, B.1.1: checkpoint every K messages, BEFORE protect.
const k: u64 = 64;
if (client_ctx.sender.needsCheckpoint(k)) try nonvolatile.write(client_ctx.sender.sequence_number);
const protected = try oscore.protect(allocator, &client_ctx, plaintext, aad, true, null);

// ... reboot ...
var client_ctx = try oscore.deriveContext(allocator, master_secret, master_salt, id_context, sender_id, recipient_id, .aes_ccm_16_64_128);
// SSN2 = SSN1 + K + F; F covers the storage's own write delay.
try client_ctx.sender.resumeAfterRestart(try nonvolatile.read(), k, 1);

// Receiving side, B.1.2: once the CoAP layer has verified ONE request as
// fresh after the reboot (Echo option, RFC 9175), its Partial IV becomes
// the window's lower limit — everything at or below it is a replay.
server_ctx.recipient.replay_window.resumeAtLowerLimit(fresh_request_option.partial_iv.?);
```

Or derive a fresh context from new randomness (Appendix B.2) — new keys
make both problems disappear. What is NOT safe is doing neither. See
[SPEC.md](SPEC.md) "Persistence" for why `highest_seen`/`mask` must not
simply be stored and reloaded.

### Limits `protect`/`unprotect` enforce

| Limit | Constant | Error |
|---|---|---|
| Plaintext per message (AES-CCM 2-byte length field) | `max_plaintext_len` = 65 535 | `error.MessageTooLong` |
| Payload `unprotect` will look at | `max_ciphertext_len` = 65 543 | `error.MessageTooLong` (before the AEAD, so never a panic) |
| Partial IV, on BOTH paths | `max_partial_iv` = 2^40 − 1 | `error.SequenceNumberExhausted` (protect) / `error.PartialIvTooLarge` (computeNonce, unprotect) |
| Sender/Recipient ID length | `id_piv_field_width` = 7 | `error.IdTooLong` |

## Import graph

```
oscore → std.crypto.aead.aes_ccm.Aes128Ccm8 / std.crypto.kdf.hkdf.HkdfSha256 / std.crypto.hash.sha2.Sha256
```

No sibling-module dependency (`meta.deps = .{}`) — deliberately not
depending on `coap`, see the module doc comment's "Scope / non-goals".

## Verify

```
zig build test-oscore                        # Debug — green
zig build test-oscore -Doptimize=ReleaseFast
zig fmt --check modules/oscore/
```

`kat_test.zig` asserts byte-exact `deriveKey`/`deriveContext`/
`computeNonce`/`buildAad`/`protect`/`unprotect` output against every RFC
8613 Appendix C.1-C.8 value, plus a tampered-ciphertext rejection, a
replayed-Partial-IV rejection, an end-to-end round trip with fresh
(non-published) key material, and the guards Appendix C is blind to
(message length, Partial IV ceiling on the receive path, real double
delivery, Class I options in the AAD, restart recovery — see SPEC.md).

Provenance: see [NOTICE](NOTICE).
