# wireguard — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Both wire directions are pure functions over byte slices — `DeviceParser.feed` (GET) and
`buildSetRequests` (SET) — so the exact netlink + genlmsghdr + nested-attribute layout is golden-byte
tested offline; the socket only ferries buffers. Multipart is handled on both sides: a GET dump
splits a device with many peers across messages, and a peer whose allowed-ips overflow continues in
the next message carrying only its public key; the parser detects the continuation (first peer of a
message, same key as the last accumulated peer) and merges into one typed `Device`. SET splits a
large config the same way `wg` does: follow-up messages repeat only the interface identity, a
continued peer never re-sends `WGPEER_F_REPLACE_ALLOWEDIPS` (which would undo earlier fragments), and
each message is ACKed before the next is sent; `max_msg_len` is a soft ceiling — one indivisible
attribute group never splits, so every message makes progress no matter how small the ceiling. Keys
are raw `[32]u8`; `keyFromBase64` is strict (exactly 44 chars, canonical re-encode) like `wg`,
rejecting non-canonical trailing bits; all-zero keys mean "unset" → `null`. Error policy: malformed
kernel replies → typed codec errors (`error.Truncated`/`BadLength`, never a panic); NLMSG_ERROR
errnos map to typed errors (`AccessDenied`, `NoSuchDevice`, …). One `Wireguard` per thread/loop; no
globals; all `Device` allocations use the `open` allocator. Depends on `netlink` for the
bounds-checked nlmsghdr+nlattr codec and on `genetlink` for the generic-netlink layer (`genlmsghdr`,
nlctrl `CTRL_CMD_GETFAMILY` resolve, `NETLINK_GENERIC` socket) — re-exported here as `genl` for
source compatibility with when it lived locally in `src/genl.zig`; that layer was extracted into its
own module (`../genetlink/`) so other genetlink families (ethtool, devlink, nl80211, …) can reuse it
without depending on `wireguard`. Clean-room from the documented WireGuard netlink UAPI
(`uapi/wireguard.h`) and the genetlink UAPI (`linux/genetlink.h`); behavior modeled after wgctrl-go
and the `wg` tool's protocol usage — attribute-shape and config-splitting reference only, no source
consulted or copied — see NOTICE.

## Provenance / licensing
The kernel UAPI headers this module cites (uapi/wireguard.h, linux/genetlink.h) are GPL-2.0, but
that does not make the module a GPL derivative: only uncopyrightable ABI facts are taken from them
(command/attribute/flag constants, struct layouts), and separately, those headers carry the
**Linux-syscall-note** exception, which explicitly permits userspace of any license to use them to
interface with the kernel. No kernel source was consulted or copied; wgctrl-go (MIT) was a
behavior-only design reference. Full attribution in /NOTICE.

## Threat model / out of scope
Both `getDevice` and `setDevice` need **CAP_NET_ADMIN** (the kernel registers the family with
`GENL_UNS_ADMIN_PERM`); family *resolve* is unprivileged. This module moves key material
(private/preshared keys) through its buffers but does not itself defend that memory (no zeroization)
— callers handle key hygiene. Untrusted input is the kernel reply, validated by the fuzzed `netlink`
codec. Out of scope (deliberate): `listDevices()` (needs rtnetlink IFLA_LINKINFO kind filtering —
belongs in `netlink`), key *generation* (X25519 via `std.crypto` — trivial for callers), the
multicast event group.

## Verification
Offline golden-byte + parser + fuzz tests are the gate: WG_CMD_SET_DEVICE request bytes (device +
peer + allowed-ip) byte-exact (LE-only), ifindex-identity/remove-peer/config validation, a large
config split across ≥2 messages then round-tripped back through the GET parser, multipart GET peer-
continuation reassembly, malformed-reply → typed error, errno mapping, a `std.testing.fuzz` harness
over the device parser. The generic-netlink transport's own golden `CTRL_CMD_GETFAMILY` request
bytes + truncated-header-rejection tests now live in and run under `zig build test-genetlink` (see
`../genetlink/SPEC.md`) — extracted, not duplicated. Live tests here: an unprivileged nlctrl
family-resolve integration test (this module's own, over the WireGuard family specifically), and a
root-gated test (skipped otherwise) that set+get round-trips a config on a real `wg` interface
created via `ip link add … type wireguard`. Run: `zig build test-wireguard`.

**External anchor** (`kernel_goldens.zig`): the netlink configuration-plane codec above was, before
this file, only ever round-tripped through its OWN encoder/decoder pair — self-consistent but blind
to a bug that is wrong the same way on both sides. `kernel_goldens.zig` freezes two bytestreams
captured ONCE inside a throwaway `unshare --user --map-root-user --net` namespace: the real
`wg`(8) tool's WG_CMD_SET_DEVICE request (an independent encoder), and — the stronger anchor — the
real kernel's own WG_CMD_GET_DEVICE reply to that configuration. Both are decoded through this
module's actual `DeviceParser`/`genl.splitPayload`, asserted against every configured field
offline, no root/kernel access needed to run the suite. `wg`'s own attribute order differs from
this module's `buildSetRequests` (netlink attribute order is not semantically significant); rather
than asserting a byte-identity that was never true between two conformant encoders, the SET
direction is cross-checked by decoding both this module's own request and `wg`'s real one to an
equal semantic `Device`.

## Backlog / deferred
The root-gated live test's `runIp()` helper shells out to the `ip` binary — the one external-process
use in the whole repo (zig-libs is otherwise 100% pure-Zig/no-exec). Flagged as a known item
in this module's own backlog (pure-Zig-invariant audit): either replace with a direct rtnetlink
`RTM_NEWLINK`/`IFLA_LINKINFO` call
(consistent with the module's own netlink-native style) or explicitly document/allowlist the
exception. `listDevices()` (rtnetlink IFLA_LINKINFO kind filtering) and the multicast event group
remain out of scope per the design.

## Cryptographic handshake (`noise.zig` / `handshake.zig`)

The Noise_IKpsk2 data-plane handshake: real wire-layout declarations
(`MessageInitiation`/`MessageResponse`/`CookieReply`/`MessageTransportHeader`, all comptime
size-asserted) and the `Handshake` state machine (`createInitiation`/`consumeInitiation`/
`createResponse`/`consumeResponse`/`deriveTransportKeys`/`computeMac1`/`computeMac2`) over std.crypto
(X25519, ChaCha20-Poly1305, keyed BLAKE2s-128 for the 16-byte mac1, HKDF-over-HMAC-BLAKE2s KDF).
Secret material (DH outputs, chaining key, ephemeral privates, KDF scratch) is `secureZero`'d;
`consumeResponse` works on copies so a forged response can't corrupt a pending handshake. No `netlink`
dependency (std.crypto only).

**Cookie / mac2 (whitepaper §5.4.7) — the under-load DoS layer.** mac1 is keyed on
`HASH(LABEL_MAC1 ‖ responder_static_public)`, a *public* value, so a mac1-passing initiation is
forgeable from a spoofed source and costs the responder an X25519 plus two AEAD opens. The cookie
layer turns that into a round-trip requirement and is implemented, not merely declared:
`CookieChecker` (responder side — the `Rm` secret rotating every 120 s, `checkMac1`/`checkMac2`,
`createReply`, and the `admit()` gate returning `accept`/`cookie_reply`/`drop` **before** any
`Handshake` exists, which is what makes it a defense rather than a formality) and `PeerCookie`
(initiator side — opens the reply, ages the cookie out after 120 s, feeds `Handshake.cookie`, which
is the single place `mac2` is either stamped or left all-zero). `under_load` and per-source reply
rate-limiting are the caller's policy: this module sees neither socket nor clock, so `now_s` and the
opaque `source_address` bytes are passed in. The cookie reply is XChaCha20-Poly1305 (`noise.XAead`,
**std, deliberately** — `chachapoly` implements RFC 8439 only and the X-variant is a different
construction; substituting it would be a silent security break, not a speed-up), keyed on
`HASH(LABEL_COOKIE ‖ responder_static_public)` with the answered message's `mac1` as associated data.

Endianness: the `extern struct` wire layouts match the WireGuard byte layout only on a little-endian
host (true of every platform this repo currently targets); a big-endian target would need explicit
`std.mem.readInt`/`writeInt(..., .little)`, the same way `root.zig`'s `parseEndpoint`/`appendEndpoint`
handle the control-plane messages. This is not left to the reader: a `comptime` guard in
`handshake.zig` turns it into a build failure with that instruction, verified to fire by
cross-compiling for `s390x-linux`. The failure mode it prevents — silently emitting byte-swapped
handshakes that no peer accepts — would otherwise surface only as an interop mystery.

Verification: WireGuard publishes no official full-handshake test vector (only KDF vectors, from
wireguard-go `device/kdf_test.go` — hardcoded here and passing). A fixed-input full-handshake KAT
(byte-exact 148 B initiation, 92 B response, and both transport keys) was generated from an independent
reference written from whitepaper §5.4, itself validated against the wireguard-go KDF vectors.
Initiator↔responder self-consistency (both sides agree the transport-key pair; tampered message /
wrong PSK fail closed). A netns-gated **live in-kernel WireGuard interop** test (Linux + euid 0 +
`unshare -rn` + `ip`/wireguard module) runs a real handshake against the kernel and AEAD-decrypts a
kernel-sent transport packet under the derived key, including a non-zero PSK.
The cookie layer has no published vector either, so it is pinned the same way: a second independent
reference (Python `hashlib.blake2s` keyed at a 16-byte parameterised output + libsodium's
XChaCha20-Poly1305 via PyNaCl, written from §5.4.7 and sharing no code with this module) fixes the
64-byte cookie reply, the cookie, and the resulting mac2 byte-exact — and that generator recomputes
the pinned KAT initiation's own mac1 from `LABEL_MAC1 ‖ Sr_pub` as its cross-check, so the vector is
tied to the already-anchored handshake rather than to our encoder. The reverse direction is covered
too: `PeerCookie.consumeReply` opens the foreign implementation's ciphertext.

## Transport data plane (`transport.zig`)

The type-4 seal/open path the handshake exists to key: `SendSession.seal` turns one plaintext packet
into `header ‖ AEAD(T_send, nonce(counter), pad16(packet), ε)`, `RecvSession.open` reverses it.
Four protocol details carry the interop risk, and each is pinned by its own test rather than by a
round trip: the nonce is **4 zero bytes ‖ counter little-endian** (byte-exact expectations for 0, 1,
2, 255, 256, 2^32−1, 2^32, an asymmetric value and 2^64−1); the **AAD is empty** (the header is not
associated data — the counter is bound through the nonce); the plaintext is **zero-padded to a
multiple of 16** with `paddedLen(0) == 0`, so a keepalive is 32 bytes on the wire and not 48; and
`open` returns the **padded** length, because WireGuard deliberately does not encode the true one —
the receiver takes it from the inner IP header, so this codec must not try to strip padding.
`seal` refuses at `REJECT_AFTER_MESSAGES` (2^64−2^13−1) instead of wrapping — a wrapped counter
repeats a nonce, which is fatal for ChaCha20-Poly1305 — mirroring the same refuse-don't-wrap stance
`aeadframe`'s sealer takes at its own ceiling. `REKEY_AFTER_MESSAGES` (2^60) is a *policy* limit
with 2^60 of margin left, so it is surfaced as a typed `RekeyState.due` on every seal and open
rather than enforced: continuing silently would be wrong, but dropping a packet the peer will still
accept would be worse. Anti-replay is an RFC-6479 circular bitmap `default_window_bits` (8192)
counters wide — the same width `REJECT_AFTER_MESSAGES` reserves below the u64 ceiling and the width
the Linux implementation uses. Counters are tracked internally as `counter + 1` so the all-zero
state means "nothing received" and counter 0 stays an ordinary first packet. `accepts` is a
read-only pre-check and `commit` runs only after the tag verifies, so a forged packet can never burn
a legitimate counter's window slot. Nothing branches on secret data: the counter, the receiver index
and the length are all cleartext header fields. Zero allocation — every entry point writes into a
caller buffer, and `seal` pads and encrypts in place inside it (`chachapoly` documents and tests the
`c == m` case).

**Why not built on the `aeadframe` sibling.** `aeadframe` is the right shape in the abstract — per-key
AEAD records, monotonic counter nonce, sliding-window anti-replay, refuse-don't-wrap — and its
`Channel` was evaluated first. It cannot be used here because WireGuard's wire format is fixed by
the protocol and differs from `aeadframe`'s in every field that matters: a 16-byte
`type ‖ reserved ‖ receiver_index ‖ counter` header (all little-endian) vs `aeadframe`'s 13-byte
`version ‖ epoch ‖ seq` (all **big**-endian); a nonce of `4 zero bytes ‖ counter LE` vs
`epoch BE ‖ seq BE`; an **empty** AAD vs a mandatory context/tenant binding; a **pad-to-16** rule
`aeadframe` has no concept of (its `sealedLen` is `overhead + pt_len`); and protocol counter limits
(`2^64−2^13−1` / `2^60`) instead of a plain u64 ceiling. Sealing through `aeadframe` and rewriting
the framing afterwards would mean re-encrypting under a different nonce — i.e. not using it at all.
The one genuinely reusable piece was `aeadframe.ReplayWindow`, whose semantics (advisory `accepts`,
post-authentication `commit`) are exactly right; it is capped at **64** counters by its `u64` bitmap,
and WireGuard's own constants reserve 8192, so a 64-wide window would drop legitimate reordered
packets on any fast link. Widening it belongs to `aeadframe`'s owner, not to a caller, so this
module implements the wider circular bitmap locally — the same relationship `aeadframe`'s own
`replay.zig` documents towards the windows in `oscore`/`snmp`/`iec62351`. No new module dependency
was added (`noise.zig` → `chachapoly`, already declared).

**Verification.** WireGuard publishes no fixed-input transport-data vector, and none was
self-generated in place of one. What anchors this: (1) the nonce layout against **literal expected
bytes** transcribed from whitepaper §5.4.6, at the counters where a byte-swap or a 32-bit truncation
shows up (a consistent nonce error is invisible to any round trip, which is why this test exists at
all) — plus a permanent positive control showing counter 0 is exactly where a big-endian nonce
*would* agree, i.e. why the handshake KATs cannot catch it; (2) a **differential over the whole
message** — the same packet rebuilt with `std.crypto.aead.chacha_poly` (an independent AEAD) over a
nonce taken from that literal table and an independently written header/padding, byte-identical at
14 payload lengths × 5 counters, then cross-opened; (3) the netns-gated **live kernel interop** test,
which now decrypts the kernel's keepalive *through `RecvSession.open`* rather than through a
hand-rolled AEAD call, making the kernel an oracle for the framing too — real, but it SKIPS without
root, so it is not counted as the offline anchor; (4) the replay window against a brute-force
reference oracle over a 20 000-step randomised trace at three widths. Behavioural tests: round trip
both directions, keepalive, send/recv keys not interchangeable, replay rejected, out-of-order-inside-
the-window accepted, the exact trailing-edge boundary (`capacity` in, `capacity + 1` out), a forged
packet not burning a window slot, `REJECT_AFTER_MESSAGES` refused on both seal and open,
`REKEY_AFTER_MESSAGES` signalled, padding at 0/1/15/16/17/31/32/1419/1420, truncated / wrong-type /
dirty-reserved-byte / wrong-receiver / tampered inputs, buffer sizing on both sides, and a
`std.testing.fuzz` harness over `open`.

**Measured** (i7-7920HQ, AVX2, ReleaseFast, `-Dcpu=native`, 1420-byte payload, `WIREGUARD_BENCH=1`):
the full `seal` path — header write, copy-and-pad, AEAD, counter limits — runs **~1.3–1.5 µs/packet
(~0.7 Mpps, ~1.0 GB/s)**, and `open` (which additionally updates the replay window) the same within
noise. The bare AEAD alone is ~1.3–1.4 µs, so the module's framing costs approximately nothing next
to the crypto; the 2.3–2.4× `chachapoly`-over-std ratio therefore survives to the API a consumer
actually calls. Still no socket, no routing table and no queue in the timed region — a real tunnel
adds a syscall (~1–2 µs) per packet on top, which will dominate.

## Status
`gap · linux · client · reentrant` + deps: `netlink`, `genetlink`, `chachapoly` — canonical source is
`pub const meta` in src/root.zig. (The handshake + transport half above depends only on
`chachapoly`/std.crypto, not on either netlink module.)
