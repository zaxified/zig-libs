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
  panic, or size an allocation — **above the KEX layer**. `KexInit.decode` is the
  exception and the one an auditor meets first: it predates the cursor and reads its ten
  name-lists through `readListOwned` → `messages.readString`, where a peer's `uint32` DOES
  size a `gpa.alloc` and the error is `StringTooLarge`/`EndOfStream`. That allocation is
  capped at `max_wire_string_len` (1 MiB), only one is live at a time, and an over-announced
  length fails `readSliceAll` and is freed by the `errdefer` — so it is bounded, not
  unbounded. Stated because an invariant an auditor is invited to rely on should not have a
  silent exception in the first message of every connection. (`transport.zig`'s `SliceReader` and `server.zig`'s `WireCursor`
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
  One list is caller-narrowable, and only downward: `ServerConfig.server_sig_algs` (below).
- **RFC 8308 extension negotiation, both roles.** The client appends `ext-info-c` and the server
  `ext-info-s` to the `kex_algorithms` they *send* (§2.1); `transport.kex_algorithms`, the list both
  sides negotiate against, never contains either, so §2.2's "if these names become negotiated as key
  exchange methods, the parties MUST disconnect" is structurally unreachable rather than checked at
  runtime. A server that saw `ext-info-c` sends `SSH_MSG_EXT_INFO` carrying `server-sig-algs` (§3.1)
  as the first packet after its `SSH_MSG_NEWKEYS` — §2.4's first opportunity, which is the one that
  matters: a client chooses its signature algorithm before its first `SSH_MSG_USERAUTH_REQUEST`. A
  client that did not advertise the indicator is sent **nothing**, not an empty message, because to
  such a peer message 7 is an unknown transport message. Both roles accept a peer's
  `SSH_MSG_EXT_INFO` at both §2.4 opportunities and ignore extensions they do not implement (§2.5);
  this module sends none as a client.
  **Why it is load-bearing rather than cosmetic:** an `ssh-rsa` key blob names no hash, so
  `rsa-sha2-256` and `rsa-sha2-512` are both valid for it and a client that is not told will not
  guess — real `ssh` logs `send_pubkey_test: no mutual signature algorithm` and never offers the key.
  `ssh-ed25519` and `ecdsa-sha2-nistp256` each have exactly one name and were never affected.
  What a server advertises is `ServerConfig.server_sig_algs`, defaulting to
  `transport.public_key_algorithms` — the four names `serveUserauth` can verify, pinned to
  `keyBlobTypeFor`/`verifySignature` by a test in both directions. A caller whose own
  `AuthorizedKeyCheck` is stricter **narrows** it; widening it would advertise a name the hook then
  refuses, leaving a client with one failed attempt and no second choice. Verification is *not*
  restricted to the advertised list — §3.1 explicitly allows a client to use an algorithm not in it.
  Client side, `userauth.authenticatePublickey` picks the strongest name the server accepts for the
  key's type from `Transport.server_sig_algs`, falling back to the key's own name when the server
  sent no extension (§3.1: a client "MUST NOT make any assumptions" then).
- **Host-key trust is entirely the caller's concern (client side).** `HostKeyVerifier` is a
  caller-supplied policy — no known_hosts file, TOFU policy or pinning lives in this module.
  Symmetrically, **user-key trust is the caller's concern on the server side**:
  `userauth.AuthorizedKeyCheck` is the one-line-of-`authorized_keys` seam, and this module never
  reads the filesystem for it.
- **Every caller-supplied policy carries a `ctx: *anyopaque` and is called through it.**
  `transport.HostKeyVerifier`, `userauth.AuthorizedKeyCheck`, `userauth.PasswordCheck` and
  `connection.CommandHandler` are `{ ctx, fn(ctx, …) }` structs, not bare `*const fn`. A process
  holding several connections gives each its own policy state without a global, which is what Go's
  `HostKeyCallback` closure and russh's `check_server_key` handler method also do. ⚠ Every slice
  handed to such a callback is borrowed for the duration of that call only — notably
  `HostKeyInfo.key_blob`, which points into the handshake's packet scratch; a callback that keeps
  one must copy it.
- **A refusal says why, to the caller — never to the peer.** `transport.HostKeyPolicy.failure` and
  `userauth.AuthConfig.failure` are optional out-pointers (the idiom `sntp` uses for its
  Kiss-o'-Death code) filled in with a `HostKeyFailure` / `AuthFailure` before the corresponding
  error is returned. They exist because an error set cannot carry a payload and one
  `error.HostKeyVerificationFailed` covered four different situations — unknown host, changed key,
  revoked key, user declined — plus this module's own signature/algorithm refusals. Nothing about
  them reaches the wire: RFC 4252 §5.1's SSH_MSG_USERAUTH_FAILURE still carries no reason at all
  (see "Known limits" below), deliberately.
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
   `HostKeyPolicy.verifier`'s verdict gates whether the client proceeds — a caller that always
   answers `.accept` has no host-key security at all, but that is a caller-policy choice this
   module deliberately does not make. The verifier is given the host and port the caller dialled
   (`HostKeyInfo.host`/`.port`) precisely so that answering it *properly* — a known_hosts lookup —
   does not require the caller to smuggle them in through a global.
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
   the `PasswordCheck` callback. The `password` method sends the secret inside an encrypted packet;
   both roles scrub the heap buffer that holds the plaintext (the client its request buffer, the
   server `serveUserauth`'s packet scratch — see "Known limits" below for why that scrub is load-
   bearing only in unsafe optimize modes), but neither can scrub `writePacket`'s internal
   stack buffer — a stack-secret-residue concern shared with every other message. OAEP/
   Bleichenbacher-style timing leaks are the `rsa` module's concern. Rekeying (RFC 4253 §9) is not
   implemented, so a very long-lived or very high-volume connection is out of policy.
   Server-side command execution is a pure callback (`connection.CommandHandler`) — this module
   never spawns a process, so all sandboxing/privilege questions are the caller's.
6. **Permanently out of scope:** TLS-anything (SSH doesn't use TLS), compression (`none` only), and
   any transport concern below the `std.Io.Reader`/`Writer` seam.

### Known limits of the userauth path (audited, deliberately not "fixed" here)

- **`AuthConfig.max_attempts` is a credential budget, not a time or packet budget.** Only a
  *rejected credential* consumes it. SSH_MSG_IGNORE, SSH_MSG_DEBUG and the RFC 4252 §7
  signature-less `publickey` *query* (answered SSH_MSG_USERAUTH_PK_OK — by definition not an
  attempt) all loop `serveUserauth` without spending budget, so an unauthenticated peer can hold
  the pre-auth state machine open for as long as it keeps sending bytes. There is deliberately no
  OpenSSH-style `LoginGraceTime`: this module never owns the socket (see the transport-agnostic
  invariant above), so a read deadline can only be imposed by the caller that created the
  `std.Io.Reader`/`Writer`. **A server exposed to the internet must set one.**
- **The §7 query phase is a public-key-authorization oracle, by RFC design.** PK_OK-versus-FAILURE
  tells an unauthenticated peer whether a given public key blob is authorized for a given user
  name; OpenSSH answers the same question the same way. Relatedly, a *signed* request naming an
  unauthorized key is rejected by `AuthorizedKeyCheck` **before** any signature verification runs,
  so the two cases are also distinguishable by timing. Both leak strictly less than the protocol
  already grants, and closing either would mean diverging from RFC 4252 — so neither is treated as
  a defect. What is *not* leaked: every rejection is the same SSH_MSG_USERAUTH_FAILURE, with the
  same continuation name-list and `partial success = false`, whatever the reason (unknown user,
  unknown method, unusable algorithm, blob-type mismatch, unauthorized key, bad signature).
- **The plaintext-password scrub is only observable in unsafe optimize modes.**
  `serveUserauth` `secureZero`s its packet scratch before freeing it, because the §8 password
  arrives in that buffer. In Debug/ReleaseSafe `std.mem.Allocator.free` already poisons the block
  with `undefined` (0xaa) and hides any omission; in ReleaseFast/ReleaseSmall that memset is
  elided and the scrub is the only thing standing between a successful login and the password
  persisting verbatim in freed heap. The regression test says so in its own comment.

## Verification

`zig build test-ssh` — **all passing, Debug and ReleaseFast native, no skips** in an
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
  session id and fails under another, the borrow-not-copy `sessionId` regression, two crafted-
  wire server tests (oversize peer string, oversize packet length → typed errors), and the
  freed-scratch password-scrub regression (see Known limits for the mode caveat).
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
    stdout and the exit status it reports (3);
  - **the two RFC 8308 lanes, which are the only tests here a foreign peer's *algorithm choice*
    can break.** (a) A real `ssh` with an **RSA** user key against our server: `ssh-ed25519` and
    `ecdsa` user keys each have exactly one signature algorithm, so a client can offer them
    knowing nothing about the server, and every other lane above is blind to `server-sig-algs`.
    (b) **Our client** with an RSA user key against a real `sshd` run with
    `PubkeyAcceptedAlgorithms=rsa-sha2-512` — an oracle for the client half, because
    `AuthKey.fromOpenSSH` hands us that key pinned to `rsa-sha2-256`, so a client that does not
    read the extension signs with a hash this `sshd` refuses. Each lane was mutation-checked
    against the *other* half of the feature and stayed green, so neither is standing in for the
    other: removing the server's `EXT_INFO` send fails only (a) (`EndOfStream` — the real client
    leaves without ever sending a credential), and making the client ignore `server-sig-algs`
    fails only (b) (`AuthenticationFailed`).

  Both live tests were confirmed to actually execute (not silently skip) by poisoning their
  assertions and observing the failures. Caveat inherited from the pre-existing live-test harness:
  each picks a random loopback port and reports `error.SkipZigTest` if the spawned `sshd` never
  listens, so a port collision can turn one live test into a skip on an individual run (observed
  once in ~10 runs); a run that reports no skips is the one that proves interop.

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
- **Nothing answers SSH_MSG_UNIMPLEMENTED (RFC 4253 §11.4).** A message this module does not
  recognise ends the connection with `error.ProtocolError`; the RFC's answer is message 3, naming
  the offending sequence number, with the connection continuing. This is why RFC 8308 §2.2 forbids
  sending `SSH_MSG_EXT_INFO` to a peer that did not advertise the indicator — an unaware peer is
  *supposed* to shrug it off, and here it would not have. It is also the shape that made the
  EXT_INFO work bidirectional: having advertised `ext-info-s`, the server must tolerate the
  client's reply rather than call it a protocol error.
- **A wrongly-guessed first KEX packet is handled server-side only.** RFC 4253 §7 lets a peer set
  `first_kex_packet_follows` and send its guessed KEX packet immediately; if the guess disagrees
  with what was negotiated, the receiver MUST discard that packet. `serverHandshake` does
  (`client_kex.first_kex_packet_follows`); `clientHandshake` decodes the server's flag and ignores
  it, so a *guessing server* would desynchronise our client by one packet. No known implementation
  guesses — OpenSSH never sets the flag — and neither side of this is covered by a test, so the
  server's discard path is untested code as much as the client's is missing code. Recorded rather
  than half-fixed: an honest fix is the mirror of the server's branch **plus** a mock peer that
  actually guesses wrong, which no harness here has.
- **The client sends no RFC 8308 extensions of its own.** It advertises `ext-info-c` (which is what
  makes the server send `server-sig-algs`) and accepts a server's `SSH_MSG_EXT_INFO`, but sends
  none itself: `delay-compression` needs compression, `no-flow-control` contradicts the §5.2 window
  accounting, and `elevation` is Windows-specific.
- **`languages_client_to_server`/`languages_server_to_client` are decoded and never read**, and the
  `reserved` `uint32` likewise. Both are per RFC 4253 §7.1: the language name-lists are advisory
  (this module sends them empty) and `reserved` is "for future extension", to be sent as 0. Named
  here only because "decoded and discarded" is otherwise indistinguishable from an oversight.
- **`kex-strict-*-v00@openssh.com` (OpenSSH's strict-KEX hardening) is not implemented and not
  advertised.** An OpenSSH client offers `kex-strict-c-v00@openssh.com` on every connection; this
  module never sends the server half, so the mode stays off, which is the safe direction —
  advertising it without the sequence-number reset and the "no unexpected messages during KEX"
  discipline it names would be the dangerous half.
- **Rekeying** (RFC 4253 §9) is still not represented in `Transport`; the fixed algorithm-menu
  constants are still not runtime-configurable. RFC 8731 publishes no curve25519-sha256 test
  vectors anywhere — its §5 is IANA Considerations only, and the RFC as a whole has no
  vectors/examples section — so there is no independent KAT to wire for it; this was a
  misstatement in an earlier revision of this note, not an open task.

## Status

`gap · any · both · single_owner` + deps: `rsa` — canonical source is `pub const meta` in
`src/root.zig`. ("`gap`" follows this repo's catalog-maturity vocabulary for "no existing
extraction source — built fresh to fill a catalog gap", not a completion status.)

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** self loopback client<->server baseline; live OpenSSH interop skips if sshd absent

**How it got there.** No external oracle exists for what remains. self-loopback can't be anchored by construction; real anchor already lives in OpenSSH interop
