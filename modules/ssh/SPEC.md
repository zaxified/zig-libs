# ssh — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Scope of this pass: RFC 4253 transport layer only** (part 1 of an eventual 3-part module).
  Userauth (RFC 4252, part 2) and connection-protocol channels (RFC 4254, part 3) are reserved
  top-level placeholders in `root.zig` (`userauth`/`openSession`/`exec`, all `@panic`) — not
  scaffolded in detail yet, and out of scope for this skeleton.
- **Layering mirrors RFC 4253 itself:** version exchange (§4.2) → KEXINIT algorithm negotiation
  (§7.1) → key exchange (curve25519-sha256, RFC 8731) → SSH_MSG_NEWKEYS both ways → the Binary
  Packet Protocol (§6) carries every subsequent message, in the clear before NEWKEYS and encrypted
  after — through the *same* `readPacket`/`writePacket` entry points either way, keyed on a
  `CipherState` that is `.none` during KEX and a real cipher afterward. This is the one structural
  decision this scaffold commits to; everything else is a stub.
- **Wire-format codec (`messages.zig`) is real, not stubbed:** `writeString`/`readString` (RFC 4251
  §5 length-prefixed byte string), `writeMpint`/`readMpint` (§5 mpint, including the
  high-bit-set-implies-leading-zero-byte rule), `writeNameList`/`readNameList` (§5 comma-joined
  name-list). These are pure data-format code with no crypto/protocol-state dependency, so
  reserving them as stubs would add no value — implementing them now also gives the
  crypto-implementation agent a tested foundation to build KEXINIT/handshake encode-decode on.
- **Transport-agnostic (`transport.zig`):** `Transport` takes an already-connected
  `std.Io.Reader`/`std.Io.Writer` pair, same shape as the sibling `opcua` module's `Connection` —
  this module never opens a socket itself.
- **Algorithm menu is fixed, not negotiable-by-config, in this scaffold:** `kex_algorithms`
  (curve25519-sha256 + the `@libssh.org` variant), `server_host_key_algorithms` (ssh-ed25519,
  rsa-sha2-256/512, ecdsa-sha2-nistp256), `encryption_algorithms`
  (chacha20-poly1305@openssh.com, aes256-ctr), `mac_algorithms` (hmac-sha2-256),
  `compression_algorithms` (none only — this module never implements compression). A
  crypto-implementation agent may need to make these runtime-configurable later; recorded as
  backlog below, not decided here.
- **Host-key trust is entirely the caller's concern.** `HostKeyVerifier` is a plain callback
  (`*const fn (key_type: []const u8, key_blob: []const u8) bool`) — no known_hosts file, TOFU
  policy, or pinning lives in this module. `rsa-sha2-*` verification is delegated to the sibling
  `rsa` module (`rsa.PublicKey.fromBytes` + `rsa.verifyPkcs1v15`, RFC 8332); ed25519/ecdsa
  verification will use `std.crypto` directly.
- **Sequence numbers are `u32`** (RFC 4253 §6.4: 32-bit, starts at 0, wraps), one per direction, not
  reset for the connection's lifetime — carried on `Chacha20Poly1305State`/
  `Aes256CtrHmacSha256State`, not on `Transport` itself (so a future rekey can swap the
  `CipherState` payload without disturbing the `Transport` struct shape).

## Threat model / out of scope

Nothing in this module is a security boundary yet — it is a compiling skeleton with no
implemented crypto or protocol logic. When implemented, the load-bearing security properties will
be: (1) the exchange hash `H` must be computed and verified exactly per RFC 8731 §4 (any
deviation is a MITM opportunity); (2) `verify_host_key`'s result must gate whether the connection
proceeds — a caller that always returns `true` has no host-key security at all, but that is a
caller-policy choice this module deliberately does not make; (3) OAEP/Bleichenbacher-style timing
leaks are the `rsa` module's concern, not this one's, for `rsa-sha2-*` verification; (4) the
Binary Packet Protocol's MAC-then-decrypt vs decrypt-then-MAC ordering and constant-time MAC
comparison are unimplemented details a crypto-implementation agent must get right per RFC 4253
§6.4 — recorded as backlog, not yet audited because nothing exists to audit. Out of scope
permanently: TLS-anything (SSH doesn't use TLS), compression (`none` only), and any transport
concern below the `std.Io.Reader`/`Writer` seam (this module never opens a socket).

## Verification

`zig build test-ssh` — currently: `messages.zig`'s round-trip tests (string incl. empty string,
oversize-length rejection, mpint incl. the high-bit zero-pad-byte rule and the zero-value case,
name-list incl. empty list) plus `transport.zig`'s and `root.zig`'s construction-only smoke tests
(algorithm name-lists non-empty, `CipherState`/`Packet`/`Transport` constructible, `meta.deps`
names `rsa`). No stub `@panic` body is ever invoked by the test suite — this is verified by the
suite passing at all (a hit stub would abort the test binary). Once RFC KAT vectors exist for a
given phase (curve25519-sha256 test vectors are published in RFC 8731 §5), that phase's
implementation should be checked against them per this repo's "protocol codec" verification harness
(CONVENTIONS.md §7).

## Backlog / deferred

Implementation order for the follow-up crypto-implementation agent (each currently a
`@panic("TODO(agent): ...")` stub in `transport.zig` unless noted):

- **P1** `exchangeVersions` (RFC 4253 §4.2 version-string exchange) — no crypto, good first step.
- **P2** `KexInit.encode`/`.decode` (RFC 4253 §7.1) — built on the already-working
  `messages.writeNameList`/`readNameList`.
- **P3** `curve25519Kex` (RFC 8731 §4: X25519 ephemeral keypair, ECDH_INIT/REPLY, exchange hash
  `H`, host-key signature verification via `verify_host_key` + `rsa.verifyPkcs1v15` for
  `rsa-sha2-*`) — verify against the RFC 8731 §5 test vectors.
- **P4** `deriveKeys` (RFC 4253 §7.2 KDF).
- **P5** `readPacket`/`writePacket` (RFC 4253 §6.1 framing) for `.none`, then for
  `chacha20-poly1305@openssh.com` (OpenSSH `PROTOCOL.chacha20poly1305`), then for
  `aes256-ctr` + `hmac-sha2-256`.
- **P6** `Transport.clientHandshake` (wires P1-P5 together) + `sendPacket`/`recvPacket`.
- **P7 (future part 2)** RFC 4252 userauth (`publickey`/`password`/`keyboard-interactive`) —
  `root.zig`'s `userauth()` placeholder should grow into this.
- **P8 (future part 3)** RFC 4254 channels (`openSession`/`exec`, window/flow-control).
- **Deferred design questions, not yet decided:** whether the fixed algorithm-menu constants
  (`kex_algorithms` et al.) should become runtime-configurable; rekeying (RFC 4253 §9, triggered by
  byte/time limits) is not represented in `Transport` at all yet; `ecdsa-sha2-nistp256` host-key
  verification needs a P-256 signature-verify path via `std.crypto` (not yet reserved beyond being
  named in `server_host_key_algorithms`).

## Status

`gap · any · client · single_owner` + deps: `rsa` — canonical source is `pub const meta` in
`src/root.zig`. ("`gap`" follows this repo's catalog-maturity vocabulary for "not yet built" — see
the `rsa` module's SPEC.md Status line for the same convention applied to another
crypto-implementation-pending module.)
