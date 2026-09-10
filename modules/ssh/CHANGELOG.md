# ssh — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **ADDITIVE, not breaking.** `ServeConfig` gained an optional
  `on_channel_open_refused` hook (`ChannelOpenRejectedHandler`, `connection.zig`), called
  whenever `serveSession` answers a `SSH_MSG_CHANNEL_OPEN` with `SSH_MSG_CHANNEL_OPEN_FAILURE`
  (a concurrent second channel, a non-`"session"` type, or a zero max-packet-size peer value).
  Closes `A1/examples/ssh.md` S3a: the wire behavior was already correct (the client always
  got the failure message), but the server side had no way to know it happened at all — a
  multiplexing client's second session silently vanished from the server's point of view.
  Default `null` keeps every existing caller's behavior byte-for-byte identical. New test
  pins that the hook fires with the same kind/reason/description the wire-level OPEN_FAILURE
  test right above it already checks. scripts/modtest ssh: 134/134 (was 133/133), ReleaseSafe
  and ReleaseFast alike.

- **2026-09-10** — **ADDITIVE, not breaking.** `HostKey.fromOpenSSH` (and its `userauth.AuthKey`
  alias) can now load an `ecdsa-sha2-nistp256` openssh-key-v1 container — new
  `parseEcdsaP256OpenSSH`, dispatched the same way `parseEd25519OpenSSH` already was. Closes
  `A1/examples/ssh.md` S4+S5: `HostKey` already had the `.ecdsa_p256` variant and `publicBlob`/
  `sign` already implemented it, so an `ssh-keygen -t ecdsa` host or user key came back
  `error.UnsupportedKeyType` from the loader alone — `example-apps/ssh-demo` carried its own
  copy of this exact parser to work around the gap (`main.zig`'s `loadUnsupportedHostKey`,
  marked "MODULE GAP, worked around here rather than fought"). A curve other than nistp256
  inside an otherwise well-formed ecdsa container is still `error.UnsupportedKeyType` (no other
  `HostKey` variant exists for it). New fixture test (`ssh-keygen -t ecdsa -b 256`) parses,
  round-trips `K_S` against `ssh-keygen`'s own `.pub`, and signs/verifies; a synthetic-container
  test pins the wrong-curve rejection. One PRE-EXISTING test had to change: it used
  `ecdsa-sha2-nistp256` as its example of an unsupported key type, which is no longer true —
  switched to `ssh-dss`, a type this module has never implemented for any loader.
  scripts/modtest ssh: 133/133 (was 131/131), ReleaseSafe and ReleaseFast alike.

- **2026-09-10** — **BEHAVIOURAL, not breaking.** `negotiate` now actually negotiates the
  compression name-list (RFC 4253 §7.1) instead of decoding it and never looking again — a
  peer offering no overlap with `["none"]` is now refused with `error.UnsupportedAlgorithm`
  during KEXINIT, on both the client and the server, where it used to sail through
  undetected. `Transport.negotiated` (`NegotiatedAlgorithms`) gained two trailing fields,
  `compression_c2s`/`compression_s2c`, additive for any caller matching by field name.
  Separately, `clientHandshake` now discards a server's wrongly-guessed first KEX packet
  (`first_kex_packet_follows`, RFC 4253 §7) instead of reading it back as the real KEX reply
  and desyncing — `serverHandshake` already did this for a client's guess; this closes the
  missing client-side twin. Neither change is reachable against a conforming peer (every
  real server offers `"none"` compression and OpenSSH never guesses); both close A1 audit
  findings #4 and #7.

- **2026-09-07** — Test-only, neither BREAKING nor BEHAVIOURAL. All six fuzz
  targets SYNTHESIZED their wire input from ranged `Smith` draws — a declared
  length here, a message count there, a `boolWeighted` bias in between. A ranged
  draw reads eight octets as a little-endian `u64` and returns the range MINIMUM
  when the word does not land in range, and after the first short read `Smith`
  discards the rest of the input, so every one of those draws was its minimum;
  and no target had a corpus, so each replayed one input for ever. ⛔ Every
  "bias" the comments described had therefore never fired once, and the comments
  said so without anyone noticing: `readString` never reached the
  `max_wire_string_len` boundary or the truncated-body case (declared length and
  bytes present were both 0, so they always agreed); `readMpint` never took the
  sign-pad-stripping branch it exists for (`raw.len > 1` was false);
  `KexInit.decode` was handed eleven EMPTY name-lists, so `readListOwned`'s
  errdefer unwind never ran; `readPacket` was handed the four octets
  `00 00 00 00` and never reached the padding-length or payload-slicing
  arithmetic; and both server loops — `serveSession` and `serveUserauth` — were
  handed a single packet whose entire payload is the octet `0x00`, so the
  channel range 90..100 and `SSH_MSG_USERAUTH_REQUEST` were never produced, and
  `servePublickey`, which the harness's own comment calls "the highest-value
  fuzz entry in the file", had never been entered. Every target now draws its
  frame WHOLE with `smith.slice` — for the two server loops as a LIST of
  length-prefixed payloads terminated by a zero-length one, so the message count
  comes out of the seed's own octets too — and every corpus is built by this
  module's own writers (`KexInit.encode`, `transport.writePacket`,
  `channelOpenPayload`, `messages.writeString`), because a KEXINIT is eleven
  chained name-lists and a USERAUTH_REQUEST five chained strings, and arbitrary
  bytes are neither. Each target has a `corpus:` guard pinning the measured
  counts plus a second number the degenerate input cannot produce — octets
  returned, algorithm names recovered, payload octets framed, sign pads actually
  stripped, and for the two server loops the octets the server WROTE BACK.
  Measured 1 replayed input and 0 of every second number before; after:
  `readString` 8 non-empty seeds / 3 accepted / 705 octets / 2 `StringTooLarge`;
  `readMpint` 8 / 6 / 100 octets / **4 sign pads stripped**; `KexInit.decode`
  7 / 3 accepted / 14 algorithm names; `readPacket` 7 / 3 / 232 payload octets;
  `serveSession` 12 channel messages delivered / 280 octets of server replies;
  `serveUserauth` 7 requests delivered / 1 authenticated / 232 octets of
  replies. Verified: `zig build test-ssh --summary all` 128/128; `zig build
  test-netconf` (the consumer) 73 pass, 2 skip; `check-fuzz-reach` ssh 6
  collapsed → 0.
- **2026-08-22** — RFC 8308 extension negotiation, both roles. Fixes a real
  interoperability defect: a real OpenSSH client would not authenticate with an
  RSA user key against this server at all. BREAKING in one small place —
  `userauth.authenticatePassword` takes an options struct.

  The module implemented no `SSH_MSG_EXT_INFO`, so it never sent
  `server-sig-algs`. An `ssh-rsa` public-key blob names no hash — RFC 8332 §3
  pairs it with both `rsa-sha2-256` and `rsa-sha2-512` — so a client that is not
  told which the server accepts will not guess. Real `ssh` says
  `send_pubkey_test: no mutual signature algorithm` and never sends the request;
  `-o PubkeyAcceptedAlgorithms=rsa-sha2-256` does not help, because the refusal
  is on the *server's* silence, not the client's list. `ssh-ed25519` and
  `ecdsa-sha2-nistp256` were unaffected, each having exactly one signature
  algorithm name — which is why 107 tests and a nine-lane live-OpenSSH interop
  suite all passed: our own client names an RSA algorithm itself, and every live
  lane used ed25519. It took building the example's server half to meet a
  foreign client holding an RSA key.

  **Server.** `serverHandshake` appends `ext-info-s` to its KEXINIT
  `kex_algorithms` (RFC 8308 §2.1) and, if the client advertised `ext-info-c`,
  sends `SSH_MSG_EXT_INFO` with `server-sig-algs` as the first packet after its
  `SSH_MSG_NEWKEYS` — the RFC's first opportunity (§2.4), which is the one that
  matters because a client decides its signature algorithm before its first
  `SSH_MSG_USERAUTH_REQUEST`. A client that did *not* advertise the indicator is
  sent nothing at all, not an empty message: to such a peer message 7 is an
  unknown transport message (§2.2). What is advertised is
  `ServerConfig.server_sig_algs`, defaulting to `transport.public_key_algorithms`
  — the four names `userauth.serveUserauth` can actually verify, tied to
  `keyBlobTypeFor`/`verifySignature` by a test in both directions so the list
  cannot drift into promising something the verifier would refuse. A caller whose
  own `AuthorizedKeyCheck` is stricter narrows it (the example does, under
  `--strict-rsa`); an empty slice suppresses the extension.

  **Client.** `clientHandshake` appends `ext-info-c`, and
  `Transport.requestService` / `userauth.awaitAuthReply` accept
  `SSH_MSG_EXT_INFO` at both of the RFC's opportunities, recording the result on
  `Transport.server_sig_algs`. `userauth.authenticatePublickey` then picks the
  strongest algorithm the server said it accepts for this key's type instead of
  naming one blind — so an RSA key that `AuthKey.fromOpenSSH` pinned to
  `rsa-sha2-256` now signs `rsa-sha2-512` when the server takes it, which also
  closes the "no supported way to ask for `rsa-sha2-512`" gap for the common
  case. If the server sent no extension the key's own name is used, unchanged:
  §3.1 says a client "MUST NOT make any assumptions" then. The indicators are
  appended only while *encoding* a KEXINIT — `transport.kex_algorithms`, the list
  both sides negotiate against, stays clean, so §2.2's "if these names become
  negotiated ... the parties MUST disconnect" cannot arise.

  Accepting a *peer's* `SSH_MSG_EXT_INFO` is not optional once the indicator is
  sent (§2.2), and OpenSSH clients always send one back
  (`publickey-hostbound@openssh.com`, `ping@openssh.com`): the server's
  service-request loop ignores it per §2.5 rather than failing, which it would
  have done before.

  **`userauth.BannerHandler`** — `awaitAuthReply` validated
  `SSH_MSG_USERAUTH_BANNER` (RFC 4252 §5.4) and then discarded it, with no seam
  at all; real `ssh` shows a server's banner and this module could not.
  `PublickeyOptions.banner` and the new `PasswordOptions.banner` deliver it, with
  the caller's `ctx`, the same idiom as the other seams. ⚠ `authenticatePassword`
  therefore takes a fifth argument, `opts: PasswordOptions` — pass `.{}` for the
  previous behaviour. §5.4's warning that the text may carry control sequences is
  the caller's to act on; the example filters it the way OpenSSH's `strnvis`
  does.

  Proof, since the missing test is the point: a new live-interop lane runs a real
  `ssh` with an **RSA** user key against our server, and a second runs **our
  client** with an RSA key against a real `sshd` configured
  `PubkeyAcceptedAlgorithms=rsa-sha2-512` — an oracle for the client half,
  because `fromOpenSSH` hands us that key pinned to SHA-256. Removing the
  server's `EXT_INFO` send fails the first (`EndOfStream` — the client leaves
  without sending a credential) and leaves the second green; making the client
  ignore `server-sig-algs` fails the second (`AuthenticationFailed`) and leaves
  the first green.

- **2026-08-22** — **BREAKING.** The four caller-supplied policy seams
  (`transport.HostKeyVerifier`, `userauth.AuthorizedKeyCheck`,
  `userauth.PasswordCheck`, `connection.CommandHandler`) were bare `*const fn` pointers.
  Writing a real client on top of them (`modules/ssh/example`) proved they hand a caller too
  little, in three ways at once: **no context pointer**, so two concurrent connections could not
  have different policies without a file-scope or per-thread global — which is exactly what the
  example had to keep; **no way to say why** a key was refused, so unknown-host, changed-key,
  revoked and user-declined all arrived as one `error.HostKeyVerificationFailed`; and **the
  host-key verifier was not told which host it was verifying**, although host+port are the lookup
  key of every `known_hosts` database. Go's `HostKeyCallback` (a closure) and russh's
  `check_server_key` (a method on the caller's own handler) both carry caller state; neither
  collapses the reason.

  Each seam is now a `{ ctx: *anyopaque, …Fn }` struct with a call method — the same idiom this
  repo already uses for caller-supplied behaviour in `bacnet`'s `Transport` and `fleetsim`'s
  `Node`. `transport.no_context` is the filler for a stateless policy. `HostKeyVerifier` is shown a
  `HostKeyInfo { host, port, key_type, key_blob }` and answers a `HostKeyVerdict`
  (`.accept` / `.reject: HostKeyRejection`, where `HostKeyRejection` is `unknown_host`,
  `key_mismatch`, `revoked`, `declined`, `other`). ⚠ `key_blob` still does **not** outlive the
  call — it points into the handshake's packet scratch, `key_type` points into it, and a callback
  that keeps either must copy it; this is now documented on `HostKeyInfo` itself rather than only
  at the call site.

  The reason travels back out through an **optional out-pointer**, the idiom `sntp` gained for its
  Kiss-o'-Death code in `f1d4dd9` and `jinja`/`ebpf` already used: an error set cannot carry a
  payload, and a caller that does not care passes `null` and pays nothing. Client side:
  `HostKeyPolicy.failure: ?*HostKeyFailure`, a union that also distinguishes **this module's** own
  refusals (`.algorithm_mismatch`, `.bad_signature`, `.unsupported_algorithm`) from the caller's
  (`.policy`), which is what lets a caller drop its "did my verifier even run?" bookkeeping. Server
  side: `AuthConfig.failure: ?*AuthFailure` (`no_acceptable_method`, `unsupported_algorithm`,
  `algorithm_mismatch`, `unauthorized_key`, `bad_signature`, `wrong_password`,
  `peer_disconnected`), holding the last refusal — what a server logs. Nothing about either reaches
  the wire: RFC 4252 §5.1 gives SSH_MSG_USERAUTH_FAILURE no reason field, deliberately, and that is
  unchanged.

  **What a consumer must do.** `transport.connect` / `Transport.clientHandshake` take a
  `HostKeyPolicy` where they took a `HostKeyVerifier`, and so do the three `*Kex` functions:

  ```zig
  // before
  var t = try ssh.transport.connect(&r, &w, gpa, verifyHostKey);
  fn verifyHostKey(key_type: []const u8, key_blob: []const u8) bool { … }

  // after
  var t = try ssh.transport.connect(&r, &w, gpa, .{
      .verifier = .{ .ctx = &my_policy, .verifyFn = MyPolicy.verify },
      .host = host, .port = port,   // what the verifier looks up; optional
      .failure = &failure,          // optional
  });
  fn verify(ctx: *anyopaque, key: ssh.transport.HostKeyInfo) ssh.transport.HostKeyVerdict { … }
  ```

  `AuthConfig.authorized_key` / `.password` and `ServeConfig.exec` / `.subsystem` take the struct
  form: `.{ .checkFn = f }` / `.{ .runFn = f }` for a stateless hook (`ctx` defaults to
  `no_context`), `.{ .ctx = &state, .checkFn = f }` otherwise. Every hook function gains
  `ctx: *anyopaque` as its first parameter. A caller that returned `bool` returns `.accept` /
  `.{ .reject = … }` for the host key; the two userauth hooks and the command handler still return
  `bool`/`u32`.

  **Sweep.** All four `*const fn` seams in the module were converted; there are no others.
  Deficiency #3 (not being told what it needs) applied only to `HostKeyVerifier` — the two userauth
  hooks already receive the whole request and the command handler the whole command, so their
  parameter lists are unchanged apart from `ctx`. Deficiency #2 is discharged for `CommandHandler`
  by the protocol itself, not by a new channel: the exit status and stderr it already returns are
  RFC 4254 §6.10's way of saying why, and they reach the client.

  **In-repo consumers updated:** `modules/netconf`'s live-interop client (which now also passes the
  host and port it dialled), the module's own loopback/live-interop harnesses in `connection.zig`
  and `server.zig`, and `modules/ssh/example`. The example is the evidence: its `host_policy`
  file-scope singleton — six `var`s, a six-variant `Outcome` enum, seven `outcome = …` assignments
  threaded through the policy code, and a `reportHostKeyFailure` that had to *guess* from them
  whether the verifier had run — is gone, replaced by one `KnownHosts` value on `runClient`'s stack
  and a plain switch over `HostKeyFailure`. The file's code-line count is unchanged (653 → 652)
  only because the reporting got richer: it can now name the three module-side refusals it
  previously could not distinguish at all.

  Nine mutation proofs, each observed red then green, all against `zig build test-ssh`
  (107 tests, no skips): dropping host/port from the seam (8 red, six of them live-`sshd`
  lanes); a fixed rejection reason (9 red); `.algorithm_mismatch` reported as `.bad_signature`
  (1 red); and one per seam for the context pointer, mutated to the exact old defect — the seam
  caching the first `ctx` it ever sees, i.e. one global policy for every connection
  (`HostKeyVerifier` 10 red incl. a crash, `PasswordCheck` 1, `AuthorizedKeyCheck` 3,
  `CommandHandler` 1) — plus two wrong-`AuthFailure` mutations. ⚠ The `CommandHandler` mutation
  **survived** the first time: the per-case handler context was a single local whose stack address
  was reused identically on every run, so substituting "the previous connection's context" was
  invisible. The harness now keeps every case's context alive at once, which is both what a real
  multi-connection server does and what makes the substitution observable. The demo was rebuilt and
  re-run against a real `sshd` on all five of its host-key paths (TOFU accept, already-known,
  changed key, `@revoked`, user declines) with byte-identical output to before the change.
- **2026-08-22** — New public field `Transport.negotiated` (`transport.NegotiatedAlgorithms`):
  the KEX/host-key/cipher/MAC wire names KEXINIT actually negotiated (RFC 4253 §7.1),
  client and server side. Before this, `clientHandshake`/`serverHandshake` computed these
  as local variables and dropped them — a caller had no way to reproduce `ssh -v`'s
  negotiation banner, which both Go's `ssh.ConnMetadata` and russh's `check_server_key`
  callback expose. Sweep of the whole handshake path (client + server) found no other
  dropped negotiated parameter worth exposing the same way (the peer's raw version-
  identification string is also currently dropped, but exposing it needs `Transport` to
  own allocated memory, a materially bigger change, left open). Lifetimes: every field
  resolves to one of this module's own `pub const` name-list entries, or (server-side host
  key) a `HostKey.algorithmName()` literal — never a slice into a peer-parsed `KexInit`'s
  name-list, which is `gpa`-freed once the handshake that decoded it returns. Fixing this
  on the server side required also fixing `server.zig`'s private `pickFirst`, which
  previously returned the match from the *client's* (freed-on-return) name-list rather
  than from this module's own static one — harmless while its result was used only
  inside `serverHandshake`, but exactly the dangling-pointer shape `NegotiatedAlgorithms`
  cannot tolerate once held past the function returning. Proven with new assertions
  against a real `sshd`/`ssh` (the existing live OpenSSH interop tests, both files):
  observed to fail (16/100 tests, exactly the live-interop ones) with the two
  `t.negotiated = ...` assignments reverted, pass restored (100/100) — Debug, ReleaseSafe
  and ReleaseFast.
- **2026-08-22** — `server.zig` and `connection.zig`'s test-only `acceptBounded` (the
  `poll(2)`-bounded accept wait every self-interop/live-interop test goes through) now
  recovers a `std.Io` cancellation. `std.posix.poll` retries on `EINTR` and a thread
  parked in it is never signalled by `Threaded` at all, so a canceled accept wait used to
  run to its full timeout and come back as `error.AcceptPollFailed` or
  `error.PeerNeverConnected` — indistinguishable from a poll failure or a peer that
  genuinely never connected. Each file's `acceptBounded` now calls the new local
  `checkCanceled` once the wait ends, on both exit paths, and surfaces `error.Canceled`
  instead. `transport.zig` needed no change — it takes a caller-supplied `Io.Reader`/
  `Io.Writer` and owns no fd (documented at its `Transport.init` in the prior commit); the
  fd this module actually owns is the listening socket behind `acceptBounded`, which is
  test infrastructure only, not part of the module's public API. Two tests cover it (one
  per file); both were confirmed to fail (`error.PeerNeverConnected` instead of
  `error.Canceled`) with the recovery reverted.
- **2026-08-13** — `meta.platform` corrected `.any` → `.linux`. No code change: the
  transport's `getrandom(2)` entropy loop already `@compileError`ed on every non-Linux
  target (verified by cross-compiling the suite to macOS, Windows and FreeBSD), so the
  old tag advertised portability the module never had. README platform lines follow.
- **2026-08-11** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  4253 §7.2.
- **2026-07-10** — New module: SSH-2.0 (RFC 4253) client + server transport.
