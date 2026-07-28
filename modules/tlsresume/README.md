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

**Status: fully implemented — codec, bookkeeping, and crypto all real,
KAT-validated against RFC 8448 (incl. the 0-RTT early-data key schedule).**
See `SPEC.md` for the per-file detail and threat model.

| File | Provides |
|---|---|
| `ticket.zig` | `NewSessionTicket` encode/decode (RFC 8446 §4.6.1, incl. the §4.2.10 `early_data`/`max_early_data_size` extension), KAT-validated against the real RFC 8448 §3 wire bytes |
| `stek.zig` | STEK ring rotation/lookup bookkeeping + AES-256-GCM ticket-blob `seal`/`open` (key id bound as AAD) |
| `psk.zig` | `derivePsk`/`earlySecret`/`binderKey`/`computeBinder`/`verifyBinder` (RFC 8446 §7.1/§4.2.11.2 HKDF/HMAC chain, byte-exact vs RFC 8448 §4) |
| `earlydata.zig` | 0-RTT early-data keys (RFC 8446 §7.1 early branch + §7.3): `clientEarlyTrafficSecret` ("c e traffic") / `earlyExporterMasterSecret` ("e exp master") / `earlyTrafficKeyIv` ("key"/"iv") + `EarlyDataContext` one-call convenience — byte-exact vs RFC 8448 §4's 0-RTT trace, incl. opening its actual encrypted early-data record |
| `replay.zig` | `obfuscateAge`/`deobfuscateAge`/`withinFreshnessWindow` (RFC 8446 §4.2.11.1) + `StrikeRegister.checkAndMark` (RFC 8446 §8/§8.1 single-use anti-replay — REQUIRED before accepting the early data `earlydata.zig` derives keys for) |
| `select.zig` | `SessionState(rms_len)` (de)serialization + `selectPsk` (the server-side §4.2.11 selection loop composing everything above) |

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
const ticket_blob = try ring.seal(plaintext, fresh_12_byte_nonce, &blob_buf);

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
);

// result.psk is the restored resumption PSK; result.selected_index is what
// the server echoes in its own pre_shared_key extension (RFC 8446 §4.2.11).
```

**0-RTT early-data keys** (`earlydata.zig`) — once the binder is verified
AND the ticket has passed `replay.StrikeRegister` (early data is replayable
without it, RFC 8446 §8/§2.3):

```zig
// One call: PSK -> early_secret -> client_early_traffic_secret -> key/iv.
// The hash is of the COMPLETE ClientHello (binders included) — not the
// truncated hash the binder uses.
const ctx = tlsresume.EarlyDataContext(Hkdf, 16) // 16 = AES-128-GCM key len
    .derive(&result.psk, complete_client_hello_transcript_hash);
// ctx.key / ctx.iv protect the client's early-data records (RFC 8446 §7.3;
// per-record nonce = ctx.iv XOR left-padded sequence number, §5.3).
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

Green in Debug + ReleaseFast: codec round-trip against the actual
RFC 8448 §3 NewSessionTicket bytes; the full §4 resumption chain
(PSK/early-secret/binder-key/binder) byte-exact; the §4 0-RTT early-data
chain ("c e traffic"/"e exp master"/key/iv) byte-exact — including opening
the trace's real encrypted early-data record and a seal/open round-trip;
STEK seal/open; strike-register replay policy; `selectPsk` end-to-end.

## Provenance

Clean-room from RFC 8446 §4.2.11/§4.2.11.1/§4.2.11.2/§4.6.1/§7.1/§8 (public
IETF specification text). Design reference (client-side label/wire shapes
studied so the server side matches them exactly, no source copied):
`ianic/tls.zig`'s `transcript.zig` (`setPreSharedSecret`, `resumptionSecret`,
`pskBinder`, the standalone `pskBinder_` RFC-8448 test helper) and
`handshake_client.zig` (`Options.SessionResumption.Ticket.obfuscatedAge`,
`makeClientHello`'s `preSharedKey`/`preSharedKeyBinder` wire construction).
See `NOTICE` for the full statement.
