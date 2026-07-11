# tlsresume

Server-side TLS 1.3 session-ticket resumption (RFC 8446 §4.2.11 / §4.6.1 /
§7.1 / §8) — engine-agnostic: no owned handshake state machine, no socket,
no ClientHello parsing. The TLS engine passes in transcript-hash bytes and
already-negotiated secrets; this module returns derived PSKs, binder
verify/reject decisions, `NewSessionTicket` wire bytes, and STEK-sealed
ticket blobs.

This fills a real gap in this collection: `dtls` (DTLS 1.3, PSK mode)
explicitly declares session resumption out of scope, and the vendored
`ianic/tls.zig` TLS 1.3 implementation only has CLIENT-side resumption
(`Options.SessionResumption`) — its `handshake_server.zig` has none.

**Status: compiling scaffold — codec + bookkeeping real, AEAD/HKDF/HMAC
crypto stubbed for a follow-up pass.** See `SPEC.md`'s per-file table and
"TODO(fable)" checklist for exactly what remains.

| File | Real | Stubbed |
|---|---|---|
| `ticket.zig` | `NewSessionTicket` encode/decode (RFC 8446 §4.6.1), KAT-validated against the real RFC 8448 §3 wire bytes | — |
| `stek.zig` | STEK ring rotation/lookup bookkeeping | AES-256-GCM ticket-blob `seal`/`open` |
| `psk.zig` | — | `derivePsk`/`earlySecret`/`binderKey`/`computeBinder` (the HKDF/HMAC crypto core; `verifyBinder`'s constant-time-compare wrapper IS real) |
| `replay.zig` | `obfuscateAge`/`deobfuscateAge`/`withinFreshnessWindow` (pure arithmetic, RFC 8446 §4.2.11.1), KAT-validated against RFC 8448 §4 | `StrikeRegister.checkAndMark` (RFC 8446 §8/§8.1 anti-replay policy) |
| `select.zig` | `SessionState(rms_len)` (de)serialization | `selectPsk` (composes everything above) |

## Import

```zig
const tlsresume = @import("tlsresume");
```

## API surface

**Issuing a ticket** (`stek.zig` + `ticket.zig`):

```zig
var ring = tlsresume.stek.DefaultRing.init(); // StekRing(3)
ring.rotate(1, fresh_32_byte_key, now_s); // caller-supplied CSPRNG key

// Serialize the session state this ticket should restore (select.zig):
const State = tlsresume.select.SessionState(32); // SHA-256 suite
const state = State{
    .resumption_master_secret = rms, // from the just-completed handshake
    .ticket_nonce = &[_]u8{ 0x00, 0x00 },
    .issued_at_ms = now_ms,
    .ticket_age_add = random_u32,
};
var plaintext_buf: [128]u8 = undefined;
const plaintext = try state.serialize(&plaintext_buf);

var blob_buf: [160]u8 = undefined;
const ticket_blob = try ring.seal(plaintext, fresh_12_byte_nonce, &blob_buf); // STUB today

const nst = tlsresume.ticket.NewSessionTicket{
    .ticket_lifetime = 3600,
    .ticket_age_add = state.ticket_age_add,
    .ticket_nonce = state.ticket_nonce,
    .ticket = ticket_blob,
};
var wire_buf: [256]u8 = undefined;
const wire_bytes = try nst.encode(&wire_buf); // real today — send after the handshake header
```

**Accepting a resumed ClientHello** (`select.zig`, composing `psk.zig` +
`replay.zig` + `stek.zig`):

```zig
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

const result = try tlsresume.select.selectPsk(
    Hkdf, Hmac, tlsresume.stek.DefaultRing, &ring,
    offered_identities, offered_binders,
    empty_transcript_hash, truncated_client_hello_transcript_hash,
    now_ms, freshness_window_ms, &open_scratch,
); // STUB today — composes psk.zig's stubs

// result.psk is the restored resumption PSK; result.selected_index is what
// the server echoes in its own pre_shared_key extension (RFC 8446 §4.2.11).
```

The `tlsresume.psk` and `tlsresume.replay` free functions
(`derivePsk`/`earlySecret`/`binderKey`/`computeBinder`/`verifyBinder`,
`obfuscateAge`/`deobfuscateAge`/`withinFreshnessWindow`) are usable
standalone by an engine that wants to wire its own selection loop instead
of `select.selectPsk`.

## Verify

```sh
zig build test-tlsresume
```

20 real tests pass today (codec round-trip against the actual RFC 8448 §3
NewSessionTicket bytes, STEK ring rotation bookkeeping, ticket-age
obfuscation against the actual RFC 8448 §4 vector, `SessionState`
packing); 8 `TODO(fable)`-tagged tests are skip-guarded pending the crypto
core (see `SPEC.md`).

## Provenance

Clean-room from RFC 8446 §4.2.11/§4.2.11.1/§4.2.11.2/§4.6.1/§7.1/§8 (public
IETF specification text). Design reference (client-side label/wire shapes
studied so the server side matches them exactly, no source copied):
`ianic/tls.zig`'s `transcript.zig` (`setPreSharedSecret`, `resumptionSecret`,
`pskBinder`, the standalone `pskBinder_` RFC-8448 test helper) and
`handshake_client.zig` (`Options.SessionResumption.Ticket.obfuscatedAge`,
`makeClientHello`'s `preSharedKey`/`preSharedKeyBinder` wire construction).
See `NOTICE` for the full statement.
