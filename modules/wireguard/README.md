# wireguard

Native **WireGuard device configuration** over the kernel's generic-netlink
API: get/set devices, peers and allowed-ips — no `wg` shell-outs.

- No maintained pure-Zig WireGuard-netlink client exists.
- **Model after:** the WireGuard genetlink UAPI (`uapi/wireguard.h`) and
  wgctrl-go (typed device/peer model, config semantics).
- **Platform:** linux (raw `std.os.linux` AF_NETLINK syscalls — a conscious
  ceiling). **Role:** client. **Concurrency:** reentrant (no globals; one
  `Wireguard` per thread/loop).
- **Deps:** `netlink` — its bounds-checked wire codec (nlmsghdr + nlattr TLV
  build/parse) is reused; `genetlink` — the generic-netlink layer
  (`genlmsghdr`, nlctrl family resolve, `NETLINK_GENERIC` socket), extracted
  into its own module so other genetlink families (ethtool, devlink,
  nl80211, …) can reuse it too. Re-exported here as `wireguard.genl` for
  source compatibility; `netaddr` — `AllowedIp.parse`'s CIDR-text parsing.
- **Privileges:** CAP_NET_ADMIN for both `getDevice` and `setDevice` (the
  kernel registers the family with `GENL_UNS_ADMIN_PERM`). Family *resolve*
  is unprivileged.

Provenance: original work of the zig-libs authors (MIT); clean-room from
the documented WireGuard netlink UAPI (`uapi/wireguard.h`, GPL-2.0 WITH
Linux-syscall-note — the command/attribute/flag constants and layouts are
the kernel's OS ABI, not copyrightable interface code) and
`linux/genetlink.h`. Behavior modeled after wgctrl-go
(golang.zx2c4.com/wireguard/wgctrl, MIT) and the `wg` tool's protocol usage —
behavior/attribute-shape reference only, no source consulted or copied. The
reserved Noise_IKpsk2 scaffold additionally names wireguard-go (MIT) and the
in-kernel WireGuard implementation (GPL-2.0) for message layout and handshake
step order only. See [`NOTICE`](NOTICE) beside this file.

## API

```zig
const wireguard = @import("wireguard");

var wg = try wireguard.Wireguard.open(gpa);
defer wg.close();

// GET: typed device + peers + allowed-ips (multipart dump reassembled).
var dev = try wg.getDevice("wg0");
defer dev.deinit(gpa);
for (dev.peers) |p| _ = .{
    wireguard.keyToBase64(p.public_key), p.endpoint, p.rx_bytes, p.tx_bytes,
    p.last_handshake_time.sec,           p.allowed_ips,
};

// SET: declarative config; null = leave untouched.
try wg.setDevice(.{
    .ifname = "wg0",
    .private_key = try wireguard.keyFromBase64(priv_b64),
    .listen_port = 51820,
    .replace_peers = true,
    .peers = &.{.{
        .public_key = try wireguard.keyFromBase64(peer_b64),
        .endpoint = .{ .v4 = .{ .addr = .{ 203, 0, 113, 5 }, .port = 51820 } },
        .persistent_keepalive_interval = 25,
        .replace_allowed_ips = true,
        .allowed_ips = &.{wireguard.AllowedIp.v4(.{ 10, 0, 0, 0 }, 24)},
    }},
});

// Remove a peer.
try wg.setDevice(.{ .ifname = "wg0", .peers = &.{
    .{ .public_key = peer_key, .remove = true },
} });
```

Keys are raw `[32]u8`; `keyToBase64` / `keyFromBase64` convert to/from the
`wg` text format (strict 44-char canonical base64). `AllowedIp.parse` accepts
the same text the `wg` tool does — CIDR notation (`"10.0.0.0/24"`) or a bare
address, which expands to `/32` (IPv4) or `/128` (IPv6):

```zig
const ip = try wireguard.AllowedIp.parse("10.0.0.0/24");
const single = try wireguard.AllowedIp.parse("192.0.2.7"); // -> /32
```

It delegates the address/prefix-length parsing itself to the sibling
`netaddr` module (`parsePrefix` / `parseIp`) rather than duplicating it, and
only converts the result to this module's wire-shaped `AllowedIp`.

Low-level, for custom
use (all `pub`): the UAPI constant tables (`WG_CMD`, `WGDEVICE_A`,
`WGPEER_A`, `WGALLOWEDIP_A`, `WGDEVICE_F`, `WGPEER_F`), the pure
`DeviceParser` / `buildSetRequests` codec pair, and `genl`
(genlmsghdr + `CTRL_CMD_GETFAMILY` resolve + generic-netlink socket — a
re-export of the `genetlink` module).

## Design notes

- **Both wire directions are pure functions** over byte slices —
  `DeviceParser.feed` (GET) and `buildSetRequests` (SET) — so the exact
  netlink + genlmsghdr + nested-attribute layout is golden-byte-tested
  offline; the socket only ferries buffers.
- **Multipart GET:** a device with many peers is split across dump
  messages, and a peer whose allowed-ips overflow a message continues in
  the next one carrying only its public key. The parser detects this
  (first peer of a message, same key as the last accumulated peer) and
  merges — the caller always sees one typed `Device`.
- **Large SET configs split** the same way the `wg` tool splits them:
  follow-up messages repeat only the interface identity; a continued peer
  never re-sends `WGPEER_F_REPLACE_ALLOWEDIPS` (which would undo earlier
  fragments); each message is ACKed before the next is sent.
- **Malformed kernel replies → typed errors** (`error.Truncated` /
  `error.BadLength` via the fuzz-tested netlink codec), never a panic;
  NLMSG_ERROR errnos map to typed errors (`error.NoSuchDevice`,
  `error.AccessDenied`, …).
- **Verification:** offline golden-byte + parser + fuzz tests are the gate;
  an unprivileged integration test exercises live nlctrl family resolution,
  and a root-gated test (skipped otherwise) round-trips a config on a real
  wg interface created via `ip link add … type wireguard`.
- **Out of scope (deliberate extension points):** `listDevices()` (needs
  rtnetlink IFLA_LINKINFO kind filtering — belongs in `netlink`), key
  generation (X25519 via `std.crypto` — trivial for callers), and the
  multicast event group.

## Cryptographic handshake (`noise.zig` / `handshake.zig`)

The Noise_IKpsk2 data-plane handshake (message wire layouts + the
`Handshake` state machine that produces/consumes them) lives alongside the
netlink control-plane code above, sharing the module because both are the
one WireGuard protocol. Implemented over `std.crypto` (X25519,
ChaCha20-Poly1305, keyed BLAKE2s-128 for mac1, HKDF-over-HMAC-BLAKE2s); no
`netlink` dependency. Verified with a full-handshake known-answer vector,
initiator↔responder self-consistency, and a netns-gated live interop
against the in-kernel WireGuard implementation. Provenance: see `/NOTICE`.

WireGuard's under-load DoS mitigation (whitepaper §5.4.7) is part of it:
`CookieChecker.admit()` decides `accept` / `cookie_reply` / `drop` for an
inbound datagram *before* any Diffie-Hellman, answering a mac1-only flood
with a 64-byte cookie reply instead of an X25519, and `PeerCookie` holds the
cookie a peer sent us so the retry carries a valid `mac2`. mac1 alone is not
a defense — its key is derived from the responder's *public* key, so anyone
can forge one. The caller supplies the load signal, the clock (`now_s`) and
the source-address bytes; the module keeps neither socket nor clock.

## Transport data — the data plane (`transport.zig`)

What the handshake keys are *for*: type-4 transport-data messages. One
outbound packet in, one wire message out; one wire message in, one packet
out — with WireGuard's own header, padding rule, counter limits and
anti-replay window. Zero allocation on both paths (caller buffers only).

```zig
const transport = wireguard.transport;

// From a completed handshake, in one call — this is what makes the
// send/recv key and the local/remote index impossible to swap. `now_s` is
// YOUR clock; it becomes the session's birth time.
var sess = hs.transportSession(is_initiator, now_s);

// Outbound: `out` must be >= transport.sealedLen(packet.len) and must not
// overlap `packet`. Every seal/open takes the current time — that is how
// REJECT_AFTER_TIME gets enforced without this module owning a clock.
var out: [transport.sealedLen(1420)]u8 = undefined;
const s = try sess.send.seal(&out, ip_packet, now_s);
if (s.rekey == .due) startNewHandshake(); // typed signal, never silent
try udp.send(out[0..s.len]);

// Inbound: demultiplex on the header first, then open under that session.
const hdr = try transport.parseHeader(datagram);   // -> receiver_index
var plain: [1440]u8 = undefined;
const o = try sess.recv.open(&plain, datagram, now_s); // Replayed / auth /
                                                       // SessionExpired
// o.len is the PADDED length — the true packet length comes from the inner
// IP header, exactly as the protocol intends.
```

- **Nonce** = 4 zero bytes ‖ counter as 8 bytes **little-endian**; **AAD is
  empty**; the plaintext is **zero-padded to a multiple of 16**
  (`paddedLen(0) == 0`, so a keepalive is a 32-byte message).
- **Counter limits are enforced, not decorative:** `seal` refuses at
  `reject_after_messages` (2^64−2^13−1) rather than wrapping a nonce, and
  every seal/open reports `RekeyState.due` once past `rekey_after_messages`
  (2^60).
- **Session lifetime is enforced too, not left to you by accident.** §6.1
  bounds a session in seconds as well as in messages, so `seal`/`open` take
  a caller-supplied `now_s` and refuse with `error.SessionExpired` at
  `reject_after_time_s` (**180 s**) after the session's birth, and report
  `RekeyState.due` from `rekey_after_time_s` (**120 s**). The module still
  reads no clock — it makes you pass one, which is the difference between a
  documented contract and a silently skipped one. A `now_s` that moves
  backwards saturates to age 0, so a clock step cannot kill a live session.
  The §6.1 timers that are genuinely yours are the *scheduling* ones, and
  they are yours by name: `REKEY_TIMEOUT`, `REKEY_ATTEMPT_TIME` and
  `KEEPALIVE_TIMEOUT` all say *when to send something*, and this module never
  sends anything.
- **`SendSession.counter` is read-only in production.** Rewinding it is
  silent nonce reuse under a live key — keystream reuse *and* a forgeable
  Poly1305 key. `seal` is the only safe way to move it; `seekUnsafeForTest`
  is the only sanctioned way to move it at all, and its name is the warning.
- **Anti-replay:** an RFC-6479-style circular bitmap 8192 counters wide (of
  which 8128 counters are usable — one 64-bit block is redundancy — the same
  width `reject_after_messages` reserves below the u64 ceiling).
  Out-of-order inside the window is accepted once; a duplicate or a
  too-old counter is `error.Replayed`. The window is committed only *after*
  the tag verifies, so a forged packet cannot burn a legitimate slot. Note
  the *pre-check* runs **before** the AEAD, which is a deliberate divergence
  from the kernel and wireguard-go — see SPEC.md and `RecvSession.open`'s
  doc-comment; if you log or meter `error.Replayed`, merge it with
  `error.AuthenticationFailed`.
- Not built on the `aeadframe` sibling — see SPEC.md for exactly why.
