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

## Status
`gap · linux · client · reentrant` + deps: `netlink`, `genetlink` — canonical source is
`pub const meta` in src/root.zig. (The handshake scaffold above has no dependency on either.)
