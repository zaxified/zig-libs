# wireguard

Native **WireGuard device configuration** over the kernel's generic-netlink
API: get/set devices, peers and allowed-ips — no `wg` shell-outs.

- **Status:** `gap` — no maintained pure-Zig WireGuard-netlink client exists.
- **Model after:** the WireGuard genetlink UAPI (`uapi/wireguard.h`) and
  wgctrl-go (typed device/peer model, config semantics).
- **Platform:** linux (raw `std.os.linux` AF_NETLINK syscalls — a conscious
  ceiling). **Role:** client. **Concurrency:** reentrant (no globals; one
  `Wireguard` per thread/loop).
- **Deps:** `netlink` — its bounds-checked wire codec (nlmsghdr + nlattr TLV
  build/parse) is reused; the generic-netlink layer (`genlmsghdr`, nlctrl
  family resolve, `NETLINK_GENERIC` socket) lives here in `src/genl.zig`.
- **Privileges:** CAP_NET_ADMIN for both `getDevice` and `setDevice` (the
  kernel registers the family with `GENL_UNS_ADMIN_PERM`). Family *resolve*
  is unprivileged.

Provenance: clean-room from the documented WireGuard netlink UAPI
(`uapi/wireguard.h`, GPL-2.0 WITH Linux-syscall-note — the command/attribute/
flag constants and layouts are the kernel's OS ABI, not copyrightable
interface code) and `linux/genetlink.h`. Behavior modeled after wgctrl-go
(golang.zx2c4.com/wireguard/wgctrl, MIT) and the `wg` tool's protocol usage —
behavior/attribute-shape reference only, no source consulted or copied.
See `NOTICE`.

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
`wg` text format (strict 44-char canonical base64). Low-level, for custom
use (all `pub`): the UAPI constant tables (`WG_CMD`, `WGDEVICE_A`,
`WGPEER_A`, `WGALLOWEDIP_A`, `WGDEVICE_F`, `WGPEER_F`), the pure
`DeviceParser` / `buildSetRequests` codec pair, and `genl`
(genlmsghdr + `CTRL_CMD_GETFAMILY` resolve + generic-netlink socket).

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
