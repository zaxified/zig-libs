# ssh — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Scope: the whole client/server path to running a remote command.** RFC 4253 transport (part 1,
  `transport.zig` + `server.zig`), RFC 4252 user authentication (part 2, `userauth.zig`) and the
  RFC 4254 connection protocol (part 3, `connection.zig`), all implemented for **both roles**.
  There are no `@panic` stubs left in this module.
- **Layering mirrors the RFCs themselves:** version exchange (§4.2) → KEXINIT algorithm negotiation
  (§7.1) → key exchange → SSH_MSG_NEWKEYS both ways → the Binary Packet Protocol (§6) carries every
  subsequent message, in the clear before NEWKEYS and encrypted after — through the *same*
  `readPacket`/`writePacket` entry points either way, keyed on a `CipherState` that is `.none`
  during KEX and a real cipher afterward. Userauth and channels add **no framing and no crypto of
  their own**: `userauth.zig`/`connection.zig` contain only message encode/decode and protocol
  state, sent through `Transport.sendPacket`/`recvPacket`. Client (`clientHandshake`) and server
  (`serverHandshake`) drive the same layering; the server reuses `transport.zig`'s packet codec,
  `KexInit` and `deriveKeys` rather than duplicating them.
- **One decoder for peer input (`messages.Cursor`).** Every message parser in the module — KEX,
  userauth, channels — decodes with the same bounds-checked cursor: `string`/`byte`/`boolean`/
  `uint32`, each checked against the buffer it was built from. An attacker-controlled `uint32`
  length can therefore only ever produce `error.ProtocolError`; it can never index out of bounds,
  panic, or size an allocation. (`transport.zig`'s `SliceReader` and `server.zig`'s `WireCursor`
  are now aliases of it, not copies.)
- **Wire-format codec (`messages.zig`):** `writeString`/`readString` (RFC 4251 §5 length-prefixed
  byte string), `writeMpint`/`readMpint` (§5 mpint, including the high-bit-set-implies-leading-
  zero-byte rule), `writeNameList`/`readNameList` (§5 comma-joined name-list), the RFC 4253 §12 /
  4252 §6 / 4254 §9 message numbers, and `Cursor`.
- **Transport-agnostic:** `Transport` takes an already-connected `std.Io.Reader`/`std.Io.Writer`
  pair, same shape as the sibling `opcua` module's `Connection` — this module never opens a socket
  itself, and never spawns a process (see the server-side `CommandHandler` seam below).
- **Algorithm menu is fixed, not negotiable-by-config:** `kex_algorithms` (mlkem768x25519-sha256,
  curve25519-sha256 + `@libssh.org`, diffie-hellman-group14-sha256/group16-sha512),
  `server_host_key_algorithms` (ssh-ed25519, rsa-sha2-256/512, ecdsa-sha2-nistp256),
  `encryption_algorithms` (chacha20-poly1305@openssh.com, aes256-ctr, aes256-gcm@openssh.com,
  aes128-gcm@openssh.com), `mac_algorithms` (hmac-sha2-256), `compression_algorithms` (none only).
- **Host-key trust is entirely the caller's concern (client side).** `HostKeyVerifier` is a plain
  callback — no known_hosts file, TOFU policy or pinning lives in this module. Symmetrically,
  **user-key trust is the caller's concern on the server side**: `userauth.AuthorizedKeyCheck` is
  the one-line-of-`authorized_keys` seam, and this module never reads the filesystem for it.
- **Userauth key material is the same union as host keys.** `userauth.AuthKey == server.HostKey`:
  the wire formats for "a public key blob plus a signature made by it" are identical whether the
  key authenticates a host during KEX or a user during RFC 4252, so `publicBlob`/`sign`/
  `algorithmName`/`fromOpenSSH` and `transport.verifySignature` are reused verbatim by both. Key
  algorithms wired end-to-end for userauth: **ssh-ed25519** (RFC 8709), **rsa-sha2-256** and
  **rsa-sha2-512** (RFC 8332 — the signature algorithm name differs from the `ssh-rsa` key-blob
  type, and the module enforces that pairing), **ecdsa-sha2-nistp256** (RFC 5656). Bare `ssh-rsa`
  (SHA-1) is deliberately **not** accepted.
- **Sequence numbers are `u32`** (RFC 4253 §6.4), one per direction, never reset — carried on the
  `CipherState` payload, not on `Transport`, so a future rekey can swap ciphers without disturbing
  the `Transport` shape.
- **Channel flow control is real, not decorative** (RFC 4254 §5.2). Each side tracks the peer's
  remaining window and its own; a sender never emits more than `min(peer window, peer maximum
  packet size, max_send_chunk)` in one packet and blocks for SSH_MSG_CHANNEL_WINDOW_ADJUST when the
  window is exhausted; a receiver credits the peer back once half its advertised window has been
  consumed. On receipt both §5.2 limits are enforced: data beyond the granted window is
  `error.WindowOverrun` and a chunk larger than the advertised `maximum packet size` is
  `error.PacketTooLarge` — refused, not buffered.

## Threat model / out of scope

Implemented and live-interop-verified against real OpenSSH in both directions (see Verification),
so the security properties below are in effect, not aspirational.

1. **Exchange hash / host-key authentication (part 1).** `H` is computed and verified exactly per
   RFC 8731 §4 / RFC 4253 §8 (client verifies the server's signature over `H`; server signs `H`).
   `verify_host_key`'s result gates whether the client proceeds — a caller that always returns
   `true` has no host-key security at all, but that is a caller-policy choice this module
   deliberately does not make.
2. **Userauth session-id binding (part 2) — the load-bearing new property.** The RFC 4252 §7
   `publickey` signature is computed over `string session_id || byte 50 || string user || string
   service || string "publickey" || boolean TRUE || string alg || string key_blob` and nothing
   else. `userauth.signedBlob` is the *single* encoder used by both the signer and the verifier, so
   the two cannot drift. The verifier always takes the session id from **its own** `Transport`,
   never from anything on the wire; the signer takes it from its own transport too
   (`authenticatePublickeyBoundTo` exists solely so the negative test can sign against a wrong one
   and watch it be rejected). Because the session id is the first KEX's exchange hash — unique per
   connection, unforgeable by a third party — a signature captured on one connection cannot be
   replayed onto another. A subtle way to lose this property is to hand the verifier a slice into a
   *copy* of the session id rather than the transport's own storage: it compiles, and it silently
   binds the signature to stack garbage. That exact bug was made and fixed during development and
   is pinned by a regression test (`sessionId borrows from the transport`).
3. **The connection protocol is unreachable before authentication.** `serveUserauth` treats any
   non-SSH_MSG_USERAUTH_REQUEST message (notably SSH_MSG_CHANNEL_OPEN) as `error.ProtocolError`,
   sends SSH_MSG_DISCONNECT and returns; the caller only reaches `serveSession` after a successful
   `AuthResult`. Failed attempts are counted and capped (`AuthConfig.max_attempts`).
4. **Peer-controlled lengths cannot panic or over-allocate.** All decoding goes through
   `messages.Cursor` (bounds-checked, typed errors); every peer string has an explicit cap
   (`max_user_len`, `max_key_blob_len`, `max_signature_len`, …); channel data is capped by the
   advertised window *and* by the caller's `max_output`/`max_input`. The Binary Packet Protocol
   caps `packet_length` at `messages.max_wire_string_len` (1 MiB).
5. **Not covered / caller's job.** Constant-time password comparison and rate limiting belong in
   the `PasswordCheck` callback. The `password` method sends the secret inside an encrypted packet
   and this module scrubs its own request buffer, but it cannot scrub `writePacket`'s internal
   stack buffer — a stack-secret-residue concern shared with every other message. OAEP/
   Bleichenbacher-style timing leaks are the `rsa` module's concern. Rekeying (RFC 4253 §9) is not
   implemented, so a very long-lived or very high-volume connection is out of policy.
   Server-side command execution is a pure callback (`connection.CommandHandler`) — this module
   never spawns a process, so all sandboxing/privilege questions are the caller's.
6. **Permanently out of scope:** TLS-anything (SSH doesn't use TLS), compression (`none` only), and
   any transport concern below the `std.Io.Reader`/`Writer` seam.

## Verification

`zig build test-ssh` — **79 tests, all passing, Debug and ReleaseFast native, 0 skipped** in an
environment with OpenSSH installed.

- **Wire codec:** `messages.zig` round-trips (string incl. empty, mpint incl. the high-bit
  zero-pad rule and zero, name-list incl. empty) plus `Cursor` bounds tests — a `0xffffffff`
  string length, an off-by-one length and a truncated length prefix are each `error.ProtocolError`.
- **Transport:** KEXINIT encode/decode, KDF-formula, per-cipher packet round-trips + tamper
  detection, RFC 3526 prime bit-lengths, degenerate-DH-value rejection.
- **Host/user keys:** `HostKey.fromOpenSSH` fixtures (ed25519 + rsa, `K_S` byte-compared against
  `ssh-keygen`'s `.pub`), ecdsa signature wire shape, error paths.
- **Userauth units:** `signedBlob` field-order/framing assertion, session-id-changes-the-message,
  the algorithm↔key-blob-type pairing table, an ed25519 signature that verifies under its own
  session id and fails under another, the borrow-not-copy `sessionId` regression, and two crafted-
  wire server tests (oversize peer string, oversize packet length → typed errors).
- **Loopback self-interop (headline, `connection.zig`)** — our client ↔ our server over a real
  loopback TCP socket, full stack each time: transport KEX → `publickey` userauth → session-channel
  open → `exec` → stdout/stderr/`exit-status` → close. Cases: two-phase publickey, direct-signature
  publickey (no query phase), `password`, and 100 KB of output squeezed through a 16 KB window
  (so window-adjust blocking actually happens, both directions).
- **Reject-teeth, each alongside the positive control that runs through the same harness:** a
  signature bound to a *different* session id → USERAUTH_FAILURE; an unauthorized public key →
  USERAUTH_FAILURE; SSH_MSG_CHANNEL_OPEN before authenticating → server `error.ProtocolError` +
  DISCONNECT; a channel request after CLOSE → `error.ChannelClosed`; a peer overrunning the
  advertised window → `error.WindowOverrun`; a chunk over the advertised maximum packet size →
  `error.PacketTooLarge`; a request for a channel that was never opened →
  `error.ChannelClosed`; a `direct-tcpip` open → SSH_MSG_CHANNEL_OPEN_FAILURE with reason
  `unknown_channel_type` (byte-asserted on the wire).
- **Live interop against real OpenSSH 10.2p1, both directions, now covering auth + exec** (gated on
  `sshd`/`ssh`/`ssh-keygen`; `error.SkipZigTest` otherwise):
  - transport-only, as before: our client ↔ a spawned real `sshd` across 7 kex×cipher
    combinations, and a real `ssh` client ↔ our server across 9;
  - **our client → real `sshd`: `publickey` authentication with an `ssh-keygen`-generated key in
    `authorized_keys`, then `exec` of a shell command, asserting stdout `hello`, stderr `oops` and
    `exit-status` 7** — the session-id binding has to be byte-exact or OpenSSH rejects the
    signature;
  - **real `ssh` client → our server: the real client's `publickey` signature verified by our
    `serveUserauth`, then `exec` served by our `serveSession`**, asserting the client's captured
    stdout and the exit status it reports (3).

  Both live tests were confirmed to actually execute (not silently skip) by poisoning their
  assertions and observing the failures. Caveat inherited from the pre-existing live-test harness:
  each picks a random loopback port and reports `error.SkipZigTest` if the spawned `sshd` never
  listens, so a port collision can turn one live test into a skip on an individual run (observed
  once in ~10 runs); a run that reports 0 skipped is the one that proves interop.

## Backlog / deferred

Parts 1-3 are implemented. What is deliberately *not* here:

- **Userauth methods:** `keyboard-interactive` (RFC 4256), `hostbased` (RFC 4252 §9), the §8
  password-*change* sub-protocol (SSH_MSG_USERAUTH_PASSWD_CHANGEREQ is rejected, not handled),
  SSH agent forwarding / `ssh-agent` client support, and OpenSSH certificate key types
  (`*-cert-v01@openssh.com`).
- **Channel requests:** `pty-req`, `shell`, `env`, `signal`, `exit-signal`, `window-change`, X11
  forwarding, and TCP/IP port forwarding with its global requests (RFC 4254 §7). Any of these
  arriving is answered SSH_MSG_CHANNEL_FAILURE / SSH_MSG_CHANNEL_OPEN_FAILURE. `exec`,
  `subsystem` and `exit-status` are implemented. NB `exit-signal` not being implemented is why
  `ExecResult.exit_status` is optional: a command killed by a signal reports no exit status.
- **One channel per connection.** `serveSession` serves exactly one `"session"` channel and
  returns; a second concurrent SSH_MSG_CHANNEL_OPEN is refused with `resource_shortage`. A
  multiplexing server (a channel table, per-channel state) is the natural next step and is not
  here.
- **Server-side stdin is batch, not a pipe.** `CommandHandler` is a one-shot function, so
  `ServeConfig.stdin_mode` chooses between buffering CHANNEL_DATA until the client's EOF and then
  running (`.collect_until_eof`, the default) or running immediately with empty stdin
  (`.ignore`). Streaming a handler's stdin/stdout as it runs would need a different handler shape.
- **Rekeying** (RFC 4253 §9) is still not represented in `Transport`; the fixed algorithm-menu
  constants are still not runtime-configurable; RFC 8731 §5's published curve25519-sha256 vectors
  are still not wired as an independent KAT.

## Status

`gap · any · both · single_owner` + deps: `rsa` — canonical source is `pub const meta` in
`src/root.zig`. ("`gap`" follows this repo's catalog-maturity vocabulary for "no existing
extraction source — built fresh to fill a catalog gap", not a completion status.)
