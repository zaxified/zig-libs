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
bounds-checked nlmsghdr+nlattr codec; the generic-netlink layer (`genlmsghdr`, nlctrl
`CTRL_CMD_GETFAMILY` resolve, `NETLINK_GENERIC` socket) lives here in `src/genl.zig`. Clean-room from
the documented WireGuard netlink UAPI (`uapi/wireguard.h`) and the genetlink UAPI
(`linux/genetlink.h`); behavior modeled after wgctrl-go and the `wg` tool's protocol usage —
attribute-shape and config-splitting reference only, no source consulted or copied — see NOTICE.

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
over the device parser, and (in `genl.zig`) golden `CTRL_CMD_GETFAMILY` request bytes + truncated-
header rejection. Live tests: an unprivileged nlctrl family-resolve integration test, and a root-gated
test (skipped otherwise) that set+get round-trips a config on a real `wg` interface created via `ip
link add … type wireguard`. 13 tests. Run: `zig build test-wireguard`.

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

Endianness: the `extern struct` wire layouts match the WireGuard byte layout only on a little-endian
host (true of every platform this repo currently targets); a big-endian target would need explicit
`std.mem.readInt`/`writeInt(..., .little)`, the same way `root.zig`'s `parseEndpoint`/`appendEndpoint`
handle the control-plane messages.

Verification: WireGuard publishes no official full-handshake test vector (only KDF vectors, from
wireguard-go `device/kdf_test.go` — hardcoded here and passing). A fixed-input full-handshake KAT
(byte-exact 148 B initiation, 92 B response, and both transport keys) was generated from an independent
reference written from whitepaper §5.4, itself validated against the wireguard-go KDF vectors.
Initiator↔responder self-consistency (both sides agree the transport-key pair; tampered message /
wrong PSK fail closed). A netns-gated **live in-kernel WireGuard interop** test (Linux + euid 0 +
`unshare -rn` + `ip`/wireguard module) runs a real handshake against the kernel and AEAD-decrypts a
kernel-sent transport packet under the derived key, including a non-zero PSK.

## Status
`gap · linux · client · reentrant` + deps: `netlink` — canonical source is `pub const meta` in
src/root.zig. (The handshake scaffold above has no dependency on `netlink`.)
