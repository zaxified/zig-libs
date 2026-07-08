# SPEC — `wireguard`

**Purpose** — Configure WireGuard devices natively over the kernel's generic-netlink API — get a
device's full state (peers, allowed-ips, handshake times, transfer counters) and apply a declarative
config (keys, listen port, peers, allowed-ips) — without shelling out to the `wg` tool. Pairs with
`netlink` as the second consumer of its wire codec.

**Model after / Seed** — clean-room from the documented WireGuard netlink UAPI (`uapi/wireguard.h`:
command/attribute/flag constants + layouts, the kernel's OS ABI) and the genetlink UAPI
(`linux/genetlink.h`). Behavior modeled after wgctrl-go (`golang.zx2c4.com/wireguard/wgctrl`) and
the `wg` tool's protocol usage — attribute-shape and config-splitting reference only, no source
consulted or copied (`NOTICE`). Depends on `netlink` for the bounds-checked nlmsghdr+nlattr codec;
the generic-netlink layer (`genlmsghdr`, nlctrl `CTRL_CMD_GETFAMILY` resolve, `NETLINK_GENERIC`
socket) lives here in `src/genl.zig`.

**Design & invariants**
- **Both wire directions are pure functions over byte slices** — `DeviceParser.feed` (GET) and
  `buildSetRequests` (SET) — so the exact netlink + genlmsghdr + nested-attribute layout is
  golden-byte-tested offline; the socket only ferries buffers.
- **Multipart is handled on both sides.** A GET dump splits a device with many peers across
  messages, and a peer whose allowed-ips overflow continues in the next message carrying only its
  public key; the parser detects the continuation (first peer of a message, same key as the last
  accumulated peer) and merges into one typed `Device`. SET splits a large config the same way `wg`
  does: follow-up messages repeat only the interface identity, a continued peer never re-sends
  `WGPEER_F_REPLACE_ALLOWEDIPS` (which would undo earlier fragments), and each message is ACKed
  before the next is sent. `max_msg_len` is a soft ceiling — one indivisible attribute group never
  splits, so every message makes progress no matter how small the ceiling.
- **Keys** are raw `[32]u8`; `keyFromBase64` is strict (exactly 44 chars, canonical re-encode) like
  `wg`, rejecting non-canonical trailing bits. All-zero keys mean "unset" → `null`.
- **Error policy:** malformed kernel replies → typed codec errors (`error.Truncated`/`BadLength`,
  never a panic); NLMSG_ERROR errnos map to typed errors (`AccessDenied`, `NoSuchDevice`, …). One
  `Wireguard` per thread/loop; no globals; all `Device` allocations use the `open` allocator.

**Threat model / out of scope** — Both `getDevice` and `setDevice` need **CAP_NET_ADMIN** (the
kernel registers the family with `GENL_UNS_ADMIN_PERM`); family *resolve* is unprivileged. This
module moves key material (private/preshared keys) through its buffers but does not itself defend
that memory (no zeroization) — callers handle key hygiene. Untrusted input is the kernel reply,
validated by the fuzzed `netlink` codec. Out of scope (deliberate): `listDevices()` (needs rtnetlink
IFLA_LINKINFO kind filtering — belongs in `netlink`), key *generation* (X25519 via `std.crypto` —
trivial for callers), and the multicast event group.

**Verification** — Offline golden-byte + parser + fuzz tests are the gate: WG_CMD_SET_DEVICE request
bytes (device + peer + allowed-ip) byte-exact (LE-only), ifindex-identity / remove-peer / config
validation, a large config split across ≥ 2 messages then round-tripped back through the GET parser,
multipart GET peer-continuation reassembly, malformed-reply → typed error, errno mapping, a
`std.testing.fuzz` harness over the device parser, and (in `genl.zig`) golden `CTRL_CMD_GETFAMILY`
request bytes + truncated-header rejection. Live tests: an unprivileged nlctrl family-resolve
integration test, and a root-gated test (skipped otherwise) that set+get round-trips a config on a
real `wg` interface created via `ip link add … type wireguard`.

**Status** — `gap · linux · client · reentrant` · deps: `netlink`.
