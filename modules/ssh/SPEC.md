# ssh — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Scope of this pass: RFC 4253 transport layer only** (part 1 of an eventual 3-part module),
  **fully implemented for both client and server roles**. Userauth (RFC 4252, part 2) and
  connection-protocol channels (RFC 4254, part 3) are reserved top-level placeholders in
  `root.zig` (`userauth`/`openSession`/`exec`, all `@panic`) — genuinely not implemented yet, and
  out of scope for this pass.
- **Layering mirrors RFC 4253 itself:** version exchange (§4.2) → KEXINIT algorithm negotiation
  (§7.1) → key exchange (curve25519-sha256, RFC 8731) → SSH_MSG_NEWKEYS both ways → the Binary
  Packet Protocol (§6) carries every subsequent message, in the clear before NEWKEYS and encrypted
  after — through the *same* `readPacket`/`writePacket` entry points either way, keyed on a
  `CipherState` that is `.none` during KEX and a real cipher afterward. Client (`transport.zig`,
  `clientHandshake`) and server (`server.zig`, `serverHandshake`) both drive this same layering;
  the server reuses `transport.zig`'s packet codec, `KexInit`, and `deriveKeys` rather than
  duplicating them, adding only the responder-role KEX exchange (`curve25519KexServer`) and
  host-key signing (`HostKey.sign`).
- **Wire-format codec (`messages.zig`):** `writeString`/`readString` (RFC 4251 §5
  length-prefixed byte string), `writeMpint`/`readMpint` (§5 mpint, including the
  high-bit-set-implies-leading-zero-byte rule), `writeNameList`/`readNameList` (§5 comma-joined
  name-list). Pure data-format code with no crypto/protocol-state dependency; the tested
  foundation the KEXINIT/handshake encode-decode is built on.
- **Transport-agnostic (`transport.zig`):** `Transport` takes an already-connected
  `std.Io.Reader`/`std.Io.Writer` pair, same shape as the sibling `opcua` module's `Connection` —
  this module never opens a socket itself.
- **Algorithm menu is fixed, not negotiable-by-config:** `kex_algorithms`
  (curve25519-sha256 + the `@libssh.org` variant), `server_host_key_algorithms` (ssh-ed25519,
  rsa-sha2-256/512, ecdsa-sha2-nistp256), `encryption_algorithms`
  (chacha20-poly1305@openssh.com, aes256-ctr), `mac_algorithms` (hmac-sha2-256),
  `compression_algorithms` (none only — this module never implements compression). Making these
  runtime-configurable is recorded as backlog below, not decided here.
- **Host-key trust is entirely the caller's concern (client side).** `HostKeyVerifier` is a plain
  callback (`*const fn (key_type: []const u8, key_blob: []const u8) bool`) — no known_hosts file,
  TOFU policy, or pinning lives in this module. `rsa-sha2-*` verification is delegated to the
  sibling `rsa` module (`rsa.PublicKey.fromBytes` + `rsa.verifyPkcs1v15`, RFC 8332);
  ed25519/ecdsa verification uses `std.crypto` directly. On the server side, `HostKey.sign`
  performs the matching ed25519/rsa-sha2-*/ecdsa signature over the exchange hash.
- **Sequence numbers are `u32`** (RFC 4253 §6.4: 32-bit, starts at 0, wraps), one per direction, not
  reset for the connection's lifetime — carried on `Chacha20Poly1305State`/
  `Aes256CtrHmacSha256State`, not on `Transport` itself (so a future rekey can swap the
  `CipherState` payload without disturbing the `Transport` struct shape).

## Threat model / out of scope

The transport layer (KEX, host-key auth, BPP) is implemented and live-interop-verified against
real OpenSSH both directions (see Verification below), so the load-bearing security properties
below are in effect, not aspirational: (1) the exchange hash `H` is computed and verified exactly
per RFC 8731 §4 (client verifies the server's signature over `H`; server signs `H` with its host
key) — any deviation here would be a MITM opportunity, and the live-interop tests exercise the
real wire format end to end; (2) `verify_host_key`'s result gates whether the client's connection
proceeds — a caller that always returns `true` has no host-key security at all, but that is a
caller-policy choice this module deliberately does not make; (3) OAEP/Bleichenbacher-style timing
leaks are the `rsa` module's concern, not this one's, for `rsa-sha2-*` sign/verify; (4) the Binary
Packet Protocol's MAC-then-decrypt vs decrypt-then-MAC ordering and MAC comparison are implemented
per RFC 4253 §6.4 and exercised by the KAT/round-trip and live-interop tests below. Userauth (RFC
4252) and channels (RFC 4254) are NOT implemented, so nothing past the raw encrypted transport
(e.g. `requestService`'s SSH_MSG_SERVICE_REQUEST/ACCEPT) is a security boundary yet. Out of scope
permanently: TLS-anything (SSH doesn't use TLS), compression (`none` only), and any transport
concern below the `std.Io.Reader`/`Writer` seam (this module never opens a socket).

## Verification

`zig build test-ssh` — 35 tests, all passing (Debug and ReleaseFast native), 0 skipped in an
environment with OpenSSH installed: `messages.zig`'s round-trip tests (string incl. empty string,
oversize-length rejection, mpint incl. the high-bit zero-pad-byte rule and the zero-value case,
name-list incl. empty list); `transport.zig`'s KEXINIT encode/decode round-trip, curve25519 KEX
self-consistency, key-derivation, and Binary-Packet-Protocol cipher tests; `server.zig`'s
`HostKey.fromOpenSSH` fixture tests (ed25519 + rsa, `K_S` checked against `ssh-keygen`'s `.pub`
blob) and error-path tests (encrypted key container, unsupported key type); and **live interop
tests against real OpenSSH 10.2p1**, gated on `sshd`/`ssh-keygen`/`ssh` being on `PATH`
(`error.SkipZigTest` otherwise): two tests spawning a real `sshd` and running `clientHandshake`
against it (chacha20-poly1305@openssh.com and aes256-ctr), and four tests spawning a real `ssh`
client against our `server.accept` (ed25519 and rsa-sha2-256/512 host keys ×
chacha20-poly1305/aes256-ctr ciphers). No stub `@panic` body (`userauth`/`openSession`/`exec`) is
ever invoked by the test suite. The KDF test checks the RFC 4253 §7.2 formula directly rather than
against published vectors; wiring in RFC 8731 §5's published curve25519-sha256 test vectors as an
independent KAT (in addition to the current self-consistency/live-interop coverage) remains
backlog, per this repo's "protocol codec" verification harness (CONVENTIONS.md §7).

## Backlog / deferred

Part 1 (transport layer, client + server) is done — P1-P6 below (and their server-side mirrors)
are implemented, not just reserved. What remains:

- **Done (client, `transport.zig`):** `exchangeVersions` (RFC 4253 §4.2), `KexInit.encode`/
  `.decode` (§7.1), `curve25519Kex` (RFC 8731 §4, incl. host-key signature verification via
  `verify_host_key` + `rsa.verifyPkcs1v15` for `rsa-sha2-*`), `deriveKeys` (§7.2 KDF),
  `readPacket`/`writePacket` (§6.1 framing) for `.none`, `chacha20-poly1305@openssh.com`, and
  `aes256-ctr`+`hmac-sha2-256`, and `Transport.clientHandshake`/`connect`/`sendPacket`/
  `recvPacket`/`requestService`.
- **Done (server, `server.zig`):** `HostKey` (openssh-key-v1 load for ed25519/rsa,
  `publicBlob`/`sign`/`algorithmName`), `curve25519KexServer` (responder-role KEX + signing),
  `serverHandshake`/`accept` — reusing the client's `KexInit`/packet-codec/`deriveKeys`/
  `Transport` rather than duplicating them.
- **P7 (future part 2)** RFC 4252 userauth (`publickey`/`password`/`keyboard-interactive`) —
  `root.zig`'s `userauth()` placeholder should grow into this. Still a genuine `@panic` stub.
- **P8 (future part 3)** RFC 4254 channels (`openSession`/`exec`, window/flow-control). Still a
  genuine `@panic` stub.
- **Deferred design questions, not yet decided:** whether the fixed algorithm-menu constants
  (`kex_algorithms` et al.) should become runtime-configurable; rekeying (RFC 4253 §9, triggered by
  byte/time limits) is not represented in `Transport` at all yet; `ecdsa-sha2-nistp256` host-key
  signature verification path is wired for the client but worth an explicit KAT; wiring RFC 8731
  §5's published curve25519-sha256 test vectors as an independent KAT (see Verification above) is
  still backlog.

## Status

`gap · any · both · single_owner` + deps: `rsa` — canonical source is `pub const meta` in
`src/root.zig`. ("`gap`" follows this repo's catalog-maturity vocabulary for "no existing
extraction source — built fresh to fill a catalog gap", not a completion status: the RFC 4253
transport layer for both `role`s (client + server) is implemented and live-interop-verified; only
the reserved userauth/channels parts remain unimplemented, tracked in Backlog above.)
