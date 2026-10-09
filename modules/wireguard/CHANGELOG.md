# wireguard — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **SECURITY FIX (panic / stack overflow write on a malformed key):**
  `keyFromBase64`/`keyFromBase64Into` checked only the text length (44); 44 base64
  characters without the trailing `=` decode to 33 octets and were decoded into the
  32-octet key — a panic in safe builds, one octet past the key in ReleaseFast. The
  decoded size is checked first now (`error.InvalidKey`). Same shape as the websocket
  key defect found by fuzzing that day; regression test.
- **2026-10-09** — `check-secret-api` refinement (struct fields named `key`/`keys`): `Session.init` and `Session.expired` carry `secret-api-ok:` markers (the first only forwards key pointers to the memcpy-only `SendSession.init`/`RecvSession.init`, the second reads the public `born_s`). No code or signature change.
- **2026-10-09** — Dead-stack burn: `noise.keyedMac` (mac1/mac2 key, cookie secret) now runs under `burn.run` (2 KiB, per handshake message); probed in the new `stackprobe2_test.zig` on `testkit.stackprobe`. No signature change.

- **2026-10-09** — **BREAKING + FIX (secrets on the dead stack, HIGH):** a new ReleaseFast stack probe (`src/stackprobe_test.zig`, 47 + 2 needles) found, per 3 runs, 183 copies of secrets in dead frames: `Keypair.fromPrivateKey` (clamped scalar), `Keypair.generate`, every `Handshake` call (ephemeral key, `es`/`ss`/`ee`/`se`, psk2 `tau` and key), `deriveTransportKeys` (both transport keys, `temp_key`), `SendSession.seal`/`RecvSession.open` (the session key) and `noise.kdf1`/`kdf2`/`kdf3`/`mixKey`. After: 0 everywhere. **API (BREAKING):** `Keypair.generate(io, out: *Keypair)` and `Keypair.fromPrivateKey(private: *const PrivateKey, out: *Keypair)` (were return values); `Handshake.deriveTransportKeys(is_initiator, out: *TransportKeys)` and `Handshake.transportSession(is_initiator, now_s, out: *transport.Session)` (were return values); `SendSession.init(self, key: *const [32]u8, receiver_index, now_s)`, `RecvSession.init(self, key, local_index, now_s)`, `Session.init(self, keys: *const TransportKeys, local_index, remote_index, now_s)` initialize in place (were return values taking the key by value); `noise.kdf2(ck, input, out: *SymmetricKey)`, `noise.kdf3(ck, input, out1, out2)`, `noise.mixKey(ck, dh, out)` write their outputs (were return values). Migration: `var kp: Keypair = undefined; try Keypair.fromPrivateKey(&priv, &kp);`, `var sess: transport.Session = undefined; hs.transportSession(true, now_s, &sess);`. The handshake calls, key generation, the KDF steps and `seal`/`open` run their body one frame down and burn (`src/burn.zig`; 8 / 4 / 4 / 1 KiB). **Cookie layer and control plane (same entry, wave 9b; probe: 126 hits per 3 runs before, 0 after, stack and freed heap):** `CookieChecker.init(our_static_public, io, now_s, out: *CookieChecker)` and `initWithSecret(our_static_public, secret: *const [32]u8, now_s, out)` write the checker to `out` (were return values; `initWithSecret` took `Rm` by value); `CookieChecker.cookieFor(io, now_s, source_address, out: *noise.Mac)` writes the cookie to `out` (was a return value). `refresh`, `checkMac2`, `createReply`/`createReplyWithNonce`, `admit` and `PeerCookie.consumeReply` keep their signatures and burn their bodies (4 KiB). Migration: `var c: CookieChecker = undefined; CookieChecker.init(pub, io, now_s, &c);`, `var cookie: noise.Mac = undefined; c.cookieFor(io, now_s, addr, &cookie);`. Additive: `keyFromBase64Into(s, out)`, `buildSetRequestsFrom(gpa, family_id, first_seq, cfg: *const Config, max)`, `DeviceParser.finishInto(out)`, `Wireguard.getDeviceInto(ifname, out)` (the by-value forms stay and keep a key copy in their own dead frame; `Config` is unchanged). Heap: the SET request is built in blocks that are wiped when released (`src/wipe.zig`), `SetRequests.deinit` zeroes its buffer, and `Device.deinit`/`DeviceParser.deinit` and the parser's peer table wipe the private key and the pre-shared keys (the probe found the key 9x and the PSK 9-15x in freed heap before). Not covered: the caller-built `Handshake` literal, `Wireguard.setDevice`/`getDevice` (need a socket; reasoning only), the by-value `Config` argument copy, the genetlink receive buffer (SPEC). No wire change; the kernel-replay and KAT tests are unchanged.

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** the handshake and data plane are anchored to the
  Linux kernel's WireGuard without root. `tools/interop.zig` (`unshare -rn zig build
  interop-wireguard -- --capture`) records both directions — the kernel's initiation answered and
  its keepalive opened; our initiation (the KAT's `msg1`, byte for byte) and a tunnelled ICMP echo
  accepted, the echo reply opened — and `src/kernel_handshake_replay.zig` replays them in every
  lane. No defect.

- **2026-09-07** — Both fuzz targets ran one fixed input. Each opened with `smith.bytes(&buf)`
  and then drew its length with `valueRangeAtMost`, which reads eight input octets as a
  little-endian u64 and returns the range minimum when fewer remain — so the length was 0 on
  every seed. `DeviceParser.feed("")` fails at `splitPayload`, and `RecvSession.open("")` fails
  at `msg.len < overhead` on the first line of `parseHeader`, so the TLV walk, the peer nest, the
  merge path, `WrongReceiver`, `MessageLimitReached`, `SessionExpired`, `Replayed` and the AEAD
  were all unreachable — and `fuzzOpen`'s `orr.len + overhead == msg.len` assertion had never
  been evaluated. `root.fuzzParser` also called `parseEndpoint(raw[0..@min(len, 28)])`: the first
  28 octets of a *genetlink payload*, where `sa_family` would have to be the command byte plus
  the version byte, so that call returned `BadLength` before reading an address octet every round
  — even under `--fuzz`. The endpoint now travels as its own slice seed. Both targets draw with
  `smith.slice`, carry corpora built by the module's own encoders (the transport corpus is sealed
  by a real `SendSession` against the harness's key — a hex corpus could not authenticate, so it
  would have tested the refusal path and reported full reach), and are pinned by guards counting
  peers, allowed IPs, endpoints, keys, opened messages and plaintext octets. Verified by
  mutation: five loosened checks are now caught, including `parseEndpoint`'s `data.len == 16`
  weakened to `>= 8`, which needed a seed that is the right family at the wrong length.

- **2026-09-02** — **BREAKING: `BuildError` gains `AttrTooLong`.** This module carried its own
  local copy of `nestEnd` with the same defect the shared one had (a bare `@intCast` of the nest
  size into a `u16` — silent truncation in ReleaseFast). No shipped path is known to reach it,
  because the builder bounds its messages with `wouldOverflow`/`startContinuation` — but "no
  caller reaches it today" is not a guard, and the duplicate meant the fix to
  `netlink.codec.nestEnd` would not have reached this file. It delegates to the shared one now
  and propagates its error. Audit 2026-09-02 (drift campaign).

- **2026-08-18** — Portability: `linux32` (`mips-linux-musl`, `mips32,soft_float`)
  compile fix in `transport.zig`'s `ReplayWindow(bits)`, no behavior change.
  Three sites indexed the circular `bitmap` with a bare `(n >> 6) & (blocks -
  1)` / `i & (blocks - 1)`, where `n`/`i` are `u64` (derived from the
  wire-attacker-controlled 64-bit counter) — narrows without an explicit
  cast, which 0.16 rejects for a 32-bit `usize` target. The masked value is
  always `< blocks` (`blocks = bits / 64`, a caller-chosen comptime constant,
  never attacker data), so it is provably representable in `usize` on any
  host width this collection targets; extracted into a `blockIndex(x: u64)
  usize` helper that does the mask-then-`@intCast`, with the bound spelled
  out in its doc comment, rather than casting each site ad hoc. This is
  `ReplayWindow`'s anti-replay bitmap index, unrelated to wire-format
  endianness. `zig build portable-wireguard-linux32` still fails after this
  fix — see below.
- **2026-08-18** — Portability investigation (no code change to the guard): confirmed
  `handshake.zig`'s big-endian `@compileError` (added 2026-07-xx audit) is a
  real, currently-necessary guard, not stale caution. `createInitiation`/
  `createResponse` store `msg.type`/`msg.sender_index`/`msg.receiver_index`
  (`u32` fields of the `extern struct` wire messages) via plain native-endian
  scalar assignment, then `computeMac1`/`stampMac2` hash `std.mem.asBytes(&msg)`
  as the wire bytes — on a big-endian host this MACs and transmits those three
  fields byte-swapped: a self-consistent but non-interoperable (and, per two
  swapped fields' worth of session-index confusion, actively wrong) handshake,
  exactly the "worse than a build failure" case the guard's doc comment
  describes. Confirmed by inspection, not just by the error message: `type`/
  `sender_index`/`receiver_index` are the only multi-byte-int fields in
  `MessageInitiation`/`MessageResponse`/`CookieReply`; every other field is a
  `[N]u8` array, byte-order-neutral regardless of host endianness. `transport.zig`
  (the data-plane seal/open, keyed by the handshake) has NO such defect and
  needed no guard: its wire (de)serialization already goes through explicit
  `std.mem.writeInt`/`readInt(..., .little)` (see `paddedLen`'s siblings around
  transport.zig:168-223), the pattern the guard's own message points to.
  The guard's fix recipe ("encode/decode the u32/u64 fields explicitly ... then
  lift this guard") is mechanically correct but understates scope: 28
  `std.mem.asBytes`/`@memcpy` call sites in this file depend on "extern struct
  memory bytes == wire bytes" (6 in production message building/parsing, ~20 in
  the KAT/interop tests that are this module's core correctness anchor — see
  the file's own doc comment on "byte-exact ... against a vector generated by
  an independent reference implementation"), and the module ships NO
  production raw-bytes-to-struct parse function today (only a test at
  `handshake.zig:2048` does the equivalent `@memcpy`) — real big-endian support
  needs that boundary designed and added, not just patched, plus re-validating
  the byte-exact KATs against the same independent reference once the wire
  encoding no longer falls out of the struct layout for free. That is a
  rewrite of the crypto data plane's wire boundary, not a bounded local patch.
  **Middle option verified empirically, not just architecturally**: a
  standalone consumer that imports this module and calls only
  `Wireguard.open`/`Wireguard.setDevice`/`keyFromBase64`/`AllowedIp.parse`
  (the netlink control plane) cross-compiles clean for `mips-linux-musl`
  today, with zero code change — `zig build-obj` for that target exits 0 and
  produces an object file. Confirmed the mechanism: Zig's per-declaration lazy
  analysis means `root.zig`'s `pub const handshake = @import("handshake.zig")`
  re-export does not by itself force analysis of `handshake.zig`'s top-level
  `comptime` guard block; only something that actually references
  `wireguard.handshake` (this module's own `test { _ = handshake; ... }`, or a
  downstream consumer's own code) does. Verified the negative too: adding `_ =
  wireguard.handshake;` to the same standalone consumer reproduces the exact
  guard error. **Recommendation: keep the guard as-is.** No known consumer
  ships this module's data plane on big-endian hardware (the one device-agent
  consumer uses only the control-plane functions above, for which the guard already
  never fires); rewriting the wire boundary now would be exactly the "rewrite
  the crypto data plane for a target nobody ships it on" trade this module has
  already declined elsewhere. `zig build portable-wireguard-linux32` fails on
  exactly this one `@compileError`, cleanly (down from 9 narrowing errors
  before the `ReplayWindow` fix above) — see `scripts/checks/portable-known-failures.tsv`.
- **2026-08-18** — New: `AllowedIp.parse` — the `wg`-tool text form of an allowed-ip
  (CIDR notation, or a bare address expanded to `/32`/`/128` the way `wg` does). Delegates
  the address/prefix-length parsing to the new sibling dependency `netaddr`
  (`parsePrefix`/`parseIp`) rather than duplicating it, and only converts the result to
  this module's wire-shaped `AllowedIp`. New error set `AllowedIpParseError`. Purely
  additive; no existing behavior changed.
- **2026-08-13** — Test-only: `handshake.zig` gained "entropy seam: the keypair
  seed, the first cookie secret and the reply nonce really draw". **Neither
  BREAKING nor BEHAVIOURAL** — no production code changed; this adds the
  coverage that was missing for three of the module's four production
  draws. Every handshake KAT here supplies `local_ephemeral`,
  `initWithSecret` or `createReplyWithNonce` deterministically, which is
  what makes them byte-exact and equally what left the real draws
  unobserved: hardcoding `Keypair.generate`'s seed left all 68 tests green.
  The new test covers `Keypair.generate` in BOTH its roles (static
  identity, and the ephemeral inside `createInitiation` — one draw site,
  two roles), `CookieChecker.init`'s first `Rm`, and `createReply`'s
  XChaCha20 nonce, and completes a handshake plus a cookie round trip on
  the drawn values so the path is a working one. The fourth draw,
  `CookieChecker.refresh`, is deliberately NOT re-asserted: "cookie secret
  rotates after two minutes" already goes red on it in isolation
  (re-measured). Verified by planting `@memset(..., 0x5a/0x42)` after each
  of the three draws INDEPENDENTLY: three runs, 68/72 each (3 skipped),
  exactly this test red every time. Its stated limit: it catches a constant
  and an ignored `io`, not a weak-but-varying PRNG; which vtable slot the
  bytes come from is pinned in `entropy`'s own suite.

- **2026-08-13** — `Keypair.generate` now draws its X25519 seed from `entropy.fill`
  (`std.Io.randomSecure`) instead of `io.random`, closing the last
  degrading draw in the module — `CookieChecker`'s secret and nonce were
  already moved. **Not breaking:** no signature changed and no new dep.

  Both handshake initiators (`createInitiation`, `createResponse`) mint
  their per-handshake ephemeral here, and callers use it for peer static
  identities too. The ephemeral is what makes a session's keys
  unrecoverable from the static keys alone; predictable, it hands a
  passive recorder every packet of that handshake's session. The body is
  std's `X25519.KeyPair.generate` with the seed source substituted.

- **2026-08-12** — `CookieChecker`'s three random draws — `init` and `refresh` for the
  rotating secret `Rm`, and `createReply` for the `encrypted_cookie`
  XChaCha20 nonce — go through the new `entropy` module (`entropy.fill`,
  i.e. `std.Io.randomSecure`) instead of `io.random`. Not breaking: `fill`
  returns `void`, so all three signatures are unchanged. `std.Io.random` is
  a CSPRNG whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`) and the default `Io.Threaded` takes it, seeding from
  pid + wall clock + an ASLR pointer. A predictable `Rm` makes every cookie
  forgeable, which is the whole security of the mac2 layer; a repeated
  nonce under one `Rm` leaks the XOR of two cookies. Both now fail closed.
  The deterministic test seams `initWithSecret` and `createReplyWithNonce`
  are untouched, so every KAT and replay test still supplies its own bytes.
- **2026-08-11** — Security audit: eleven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: KDF
  byte-exact vs the official wireguard-go `device/kdf_test.go` vectors
  (`noise.zig:234-272`); `Ck0`/`H0` cross-checked vs independent Python BLAKE2s
  (`:291-306`).
