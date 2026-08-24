# devlink

Native **device management** over the kernel's `devlink` generic-netlink
family: enumerating devlink instances and their switch ports, reading and
writing driver parameters, walking the recursive hardware-resource tree, taking
and reading region snapshots, watching health reporters, reading firmware
inventory and switching the embedded switch's mode — no `devlink` shell-out, no
`/sys` parsing, no libc.

- No maintained pure-Zig devlink client exists.
- **Model after:** the kernel UAPI (`linux/devlink.h`). The iproute2 `devlink`
  binary was used **only as a black-box capture oracle** under `strace` — its
  requests are the byte-exact goldens this module is asserted against — no
  iproute2 source was read or ported.
- **Platform:** linux (raw `std.os.linux` AF_NETLINK syscalls — a conscious
  ceiling). **Role:** client. **Concurrency:** reentrant (no globals; one
  `Devlink` / `EventSocket` per thread/loop).
- **Deps:** `genetlink` — the generic-netlink layer (`genlmsghdr`, nlctrl
  family and multicast-group resolve, `NETLINK_GENERIC` socket), re-exported
  here as `devlink.genl`; `netlink` — its bounds-checked wire codec,
  re-exported as `devlink.codec`.
- **Privileges:** enumeration and the reads are **unprivileged**, except the
  two the kernel marks `GENL_ADMIN_PERM` — `ESWITCH_GET` and `REGION_READ`.
  Every write needs **CAP_NET_ADMIN**. Resolving and joining the `config`
  multicast group needs none.

Provenance: original work of the zig-libs authors (MIT); clean-room from the
kernel UAPI `linux/devlink.h` (GPL-2.0+ WITH Linux-syscall-note — the
command/attribute/flag constants and nest layouts are the kernel's OS ABI, not
copyrightable interface code), relying on the same Linux-syscall-note exception
as `netlink`/`genetlink`/`ethtool`/`nl80211`/`wireguard`. iproute2's `devlink`
(GPL-2.0) was run ONLY as a black-box test oracle under `strace`, its request
bytes diffed against this module's — no iproute2 source consulted, studied or
ported.

## Most machines have no devlink device

Worth knowing before the first run. The family is registered by any kernel
built with `CONFIG_NET_DEVLINK`, but *instances* are created only by SmartNIC
and switch-ASIC drivers — mlx4, mlx5, ice, bnxt, nfp, mlxsw, prestera, sja1105,
… — and by `netdevsim`. An e1000e or an iwlwifi radio registers none.

`devices()` then returns an **empty slice**, which is a correct answer and not
an error; `devlink dev show` prints nothing on the same machine. The live tests
in this module are written for that case and pass on it.

## Scope

| | |
|---|---|
| **Implemented** | `GET` (device enumeration), `PORT_GET`/`PORT_SET`/`PORT_SPLIT`/`PORT_UNSPLIT`, `PARAM_GET`/`PARAM_SET`, `RESOURCE_DUMP`/`RESOURCE_SET`, `REGION_GET`/`REGION_NEW`/`REGION_DEL`/`REGION_READ`, `HEALTH_REPORTER_GET`/`HEALTH_REPORTER_RECOVER`, `ESWITCH_GET`/`ESWITCH_SET`, `INFO_GET`, the `config` multicast group |
| **Escape hatch** | `Devlink.raw` — any command, caller-encoded attributes, replies handed back as attribute bytes |
| **Deferred** | rate objects, traps / trap groups / trap policers, DPIPE, shared buffers (`SB_*`), flash update, selftests, linecards, `RELOAD`, port functions, `PORT_NEW`/`PORT_DEL`, health diagnose/dump, `NOTIFY_FILTER_SET` — all reachable through `raw`; see `SPEC.md` |

## API

```zig
const devlink = @import("devlink");

var dl = try devlink.Devlink.open(gpa);   // resolves the family id — never hardcode it
defer dl.close();

// ── devices ──────────────────────────────────────────────────────────────
const devices = try dl.devices();          // empty on a machine with no SmartNIC
defer gpa.free(devices);
for (devices) |d| std.debug.print("{f}\n", .{d.handle});   // "pci/0000:65:00.0"

const h = devlink.Handle.pci("0000:65:00.0");     // or Handle.parse("pci/0000:65:00.0")

var info = try dl.info(h);                 // driver name, serials, firmware inventory
defer info.deinit(gpa);
_ = info.driverName();
_ = info.find(.running, "fw.version");
if (info.hasPendingUpdate()) { /* flashed, waiting for a reset */ }

// ── ports ────────────────────────────────────────────────────────────────
const ports = try dl.ports(h);             // h is applied client-side; null = all
defer gpa.free(ports);
for (ports) |p| _ = .{ p.index, p.type, p.flavour, p.netdevName(), p.isSplit() };

const one = try dl.port(.{ .handle = h, .index = 1 });
try dl.setPortType(one.portHandle().?, .eth);      // CAP_NET_ADMIN
try dl.splitPort(one.portHandle().?, 4);           // CAP_NET_ADMIN
try dl.unsplitPort(one.portHandle().?);            // CAP_NET_ADMIN

// ── parameters ───────────────────────────────────────────────────────────
const params = try dl.params(h);
defer devlink.freeParams(gpa, params);
for (params) |p| {
    _ = .{ p.name(), p.generic, p.type };
    if (p.forCmode(.runtime)) |v| _ = v.value;      // null value = "supported, unset"
    if (p.reloadWouldChange()) { /* runtime and driverinit disagree */ }
}

var single = try dl.param(h, "enable_roce");
defer single.deinit(gpa);

try dl.setParam(h, "max_macs", .driverinit, .{ .uint32 = 128 });   // CAP_NET_ADMIN
try dl.setParam(h, "enable_roce", .runtime, .{ .flag = true });

// ── resources (recursive) ────────────────────────────────────────────────
var res = try dl.resources(h);
defer res.deinit(gpa);
if (res.find("linear")) |r| _ = .{ r.size, r.occ, r.size_min, r.size_max, r.hasPendingSize() };
try dl.setResourceSize(h, res.find("linear").?.id.?, 65536);       // CAP_NET_ADMIN

// ── regions and snapshots ────────────────────────────────────────────────
const regions = try dl.regions(h);
defer gpa.free(regions);
for (regions) |r| _ = .{ r.name(), r.size, r.snapshots(), r.canSnapshot() };

const id = try dl.newSnapshot(h, "cr-space", null);   // CAP_NET_ADMIN; null = kernel picks
defer dl.delSnapshot(h, "cr-space", id) catch {};

var data = try dl.readRegion(h, .{                    // CAP_NET_ADMIN
    .region = "cr-space",
    .snapshot_id = id,
    .address = 0,
    .length = 4096,
});
defer data.deinit(gpa);
if (!data.isComplete()) { /* short read: `data.covered` of `data.bytes.len` arrived */ }

// ── health reporters ─────────────────────────────────────────────────────
const reporters = try dl.healthReporters(h);
defer gpa.free(reporters);
for (reporters) |r| _ = .{ r.name(), r.isHealthy(), r.err_count, r.unrecoveredCount(), r.hasDump() };
try dl.recoverHealthReporter(h, "fw");    // CAP_NET_ADMIN — usually resets the device

// ── eswitch ──────────────────────────────────────────────────────────────
const es = try dl.eswitch(h);             // privileged read (GENL_ADMIN_PERM)
_ = .{ es.mode, es.inline_mode, es.encap_mode, es.isSwitchdev() };
try dl.setEswitch(h, .{ .mode = .switchdev });     // CAP_NET_ADMIN; disruptive

// ── anything not modelled above ──────────────────────────────────────────
const replies = try dl.raw(.{ .cmd = devlink.uapi.CMD.TRAP_GET, .dump = true });
defer devlink.Devlink.freeRawReplies(gpa, replies);
```

Sub-namespaces, all `pub`: `uapi` (every constant and enum), `handle`, `dev`,
`port`, `param`, `resource`, `region`, `health`, `eswitch`, `client`,
`request`, plus `genl` and `codec` for driving `raw`. Every encoder and decoder
is a pure function over byte slices, so the wire format is testable without a
socket.

## Encoding a request is a public step

Every command above has a `buildX` that returns the **complete** netlink
message — nlmsghdr, genlmsghdr, flags and attributes — instead of only the
attributes. The two things a message needs that a socket owns are parameters:
the family id (whatever nlctrl assigned this boot) and the sequence number.

```zig
const msg = try devlink.buildSetPortType(gpa, dl.family_id, seq, port_handle, .eth);
defer gpa.free(msg);
// Send it over a socket of your own, keep the bytes, or hand the attribute
// half — everything past the 20-byte nlmsghdr+genlmsghdr, `msg[20..]` — to
// `Devlink.raw`, which frames the headers itself.
```

There is one per request-performing `Devlink` method — `buildDevices`,
`buildInfo`, `buildPorts`, `buildPort`, `buildSetPortType`, `buildSplitPort`,
`buildUnsplitPort`, `buildParams`, `buildParam`, `buildSetParam`,
`buildResources`, `buildSetResourceSize`, `buildRegions`, `buildRegion`,
`buildNewSnapshot`, `buildDelSnapshot`, `buildReadRegion`,
`buildHealthReporters`, `buildHealthReporter`, `buildRecoverHealthReporter`,
`buildEswitch`, `buildSetEswitch` — and **the client methods call exactly
these**, so what a builder returns is what the client sends. `NLM_F_DUMP` is
part of the message and is therefore the builder's business, not the sender's.

## The handle is two strings, not an ifindex

A devlink instance is named by `DEVLINK_ATTR_BUS_NAME` + `DEVLINK_ATTR_DEV_NAME`
— `pci/0000:65:00.0`, `netdevsim/netdevsim1`, `auxiliary/mlx5_core.eth.0` — and
a port adds `DEVLINK_ATTR_PORT_INDEX`. There is no ifindex form, and there is
no `*_HEADER` nest the way ethtool has one: the two strings sit as ordinary
top-level attributes of every message, request and reply alike.

`Handle` borrows its strings and is what you pass in; `handle.Owned` copies
them inline and is what every decoder hands back, so a decoded device outlives
the socket's receive buffer. `Owned.borrow()` turns one back into the other and
`{f}` prints the `bus/dev` form the CLI takes.

**A devlink port is not a netdev.** It is the switch-side object. Whether a
netdev is attached, and what it is called, is an attribute of the port
(`netdevName()`, `netdev_ifindex`) and is frequently absent — a CPU port, an
unused port or a `pci_vf` representor may have none at all.

## A parameter's type comes over the wire

`DEVLINK_ATTR_PARAM_VALUE_DATA` is declared `dynamic` in the UAPI: its width is
whatever `DEVLINK_ATTR_PARAM_TYPE` says, and that arrives *in the same nest*.
So the decoder cannot be a flat attribute-to-field table; it reads the type
first and then dispatches. `param.Value` is the resulting tagged union
(`uint8`/`uint16`/`uint32`/`uint64`/`string`/`flag`/`binary`/`unknown`), and a
type this module does not model keeps its raw bytes rather than being dropped.

On the way out, `setParam` derives `PARAM_TYPE` **from the value** — so the
declared type and the width of the data that follows it can never disagree,
which is the one mistake this message shape invites.

One parameter carries one value *per configuration mode*, and they routinely
differ:

| cmode | when it takes effect |
|---|---|
| `runtime` | immediately |
| `driverinit` | at the next `devlink dev reload` |
| `permanent` | stored in the device's NVM; survives a power cycle |

`Param.forCmode` returns the entry; an entry that exists with a **null value**
means "this mode is supported but currently unset", which is different from the
mode not being supported at all. `Param.reloadWouldChange()` compares runtime
against driverinit.

## Resources are recursive, and the wire does not bound them

`DEVLINK_ATTR_RESOURCE_LIST` contains `RESOURCE` nests, each of which may
contain another `RESOURCE_LIST`. Nothing on the wire caps the depth, and a
64 KiB netlink message can nest thousands of levels — enough to blow the stack
of a naive recursive-descent parser long before the buffer runs out.

So `resource.parse` carries an explicit `max_depth` (8; real drivers use 2) and
a `max_nodes` budget (1024), and a stream that exceeds either is
`error.TooDeep` / `error.TooManyResources`. A 2000-level hostile stream is a
committed test.

## Region reads are chunked and addressed

`REGION_READ` is sent with `NLM_F_DUMP`; the kernel answers with as many
messages as it needs, each carrying `REGION_CHUNK { DATA, ADDR }` entries. Note
what is *not* in a reply chunk: a length (it is the `DATA` attribute's length)
and any ordering guarantee. Chunk boundaries are wherever the kernel's message
budget landed, so the reply must be reassembled **by address**, not by
concatenation.

`region.Assembler` does that, and answers the question concatenation cannot —
*did every byte arrive?* A chunk outside the requested window, or one
overlapping a chunk already placed, is `error.BadLength` rather than something
to paper over; a short read is reported through `Data.isComplete()` /
`Data.covered` rather than as an error, because a device legitimately returning
less than was asked for is not a protocol violation.

`readRegion` with `snapshot_id = null` asks for a **direct** read of live
device memory and sets `DEVLINK_ATTR_REGION_DIRECT`; only a region whose driver
opted in allows it.

## Watching for notifications

devlink publishes one multicast group, `config`, and everything is emitted on
it: a device appearing, a port changing type, a parameter being written, a
snapshot being taken, a health reporter tripping, flash-update progress.

Unlike ethtool, devlink has **no separate `*_NTF` command namespace** — the
kernel multicasts the same `NEW`/`DEL` commands it uses for replies, so "is
this a notification" cannot be answered from the command byte alone.
`uapi.isNotifyCommand` reports the closest true thing: whether this is a
command the kernel ever multicasts.

`EventSocket` exposes **exactly one blocking call**, `waitForNotification`,
which does one `recvmsg` when its buffer is drained. There is no timer thread,
no deadline and no event loop in this module — a caller that needs a bounded
wait polls `events.fd()` itself:

```zig
var events = try devlink.EventSocket.openWith(&dl, &.{devlink.mcast_group.config});
defer events.close();

var pfd = [_]std.os.linux.pollfd{.{ .fd = events.fd(), .events = 1, .revents = 0 }};
if (std.os.linux.poll(&pfd, 1, 5000) > 0) {
    var n = try events.waitForNotification(gpa);
    defer n.deinit(gpa);
    if (n.cmd == devlink.uapi.CMD.PORT_NEW) {
        const p = try devlink.port.parse(n.attrs);   // same payload as a GET reply
        _ = p;
    }
}
```

Same seam discipline as the sibling `ethtool`, `nl80211`, `netconf` and `ebpf`
modules: threading policy belongs to the application.

## Design notes

- **The family id is resolved, never hardcoded** — it was 25 on the development
  machine and is whatever nlctrl assigns on the next boot. So is the `config`
  group id.
- **Dumps do not filter.** devlink's dump handlers walk every instance, so the
  handle passed to `ports`/`params`/`regions`/`healthReporters` is applied
  client-side. That is what the `devlink` binary does too, and it is why those
  take an *optional* handle. The single-object forms (`port`, `param`,
  `region`, `healthReporter`, `info`, `eswitch`, `resources`) are real `doit`
  requests and do carry the handle to the kernel.
- **Absent means "n/a", not zero.** Every reply field is an optional and
  nothing is defaulted. Symmetrically, an absent field in a `*Set` struct means
  "leave it alone".
- **Extended ACKs are on.** The shared transport sets `NETLINK_EXT_ACK`, so a
  refusal carries the kernel's own sentence; `lastErrorMessage` returns it out
  of the transport's buffer. `error.NotSupported` alone loses the interesting
  half.
- **Writes are destructive and are treated as such.** `recoverHealthReporter`
  runs a driver's recovery routine, which on most drivers resets the device;
  `setEswitch` mode changes tear down and re-create VF netdevs; `setParam` in
  `permanent` cmode writes the card's NVM. No test in this module issues any of
  them, not even under privilege.
- **Malformed kernel replies → typed errors** (`error.Truncated` /
  `error.BadLength` from the fuzz-tested netlink codec, plus this module's
  `TooDeep`/`TooManyResources`), never a panic. Names, snapshot lists, value
  lists, resource trees and region windows are all bounded before anything is
  allocated.

## Verify

```sh
zig build test-devlink                  # Debug
zig build test-devlink --release=fast
```

Offline golden-byte, decoder, hostile-input and fuzz tests are the gate. The
live tests run real unprivileged requests against this machine's kernel; on a
machine with no devlink instance — which is the common case — they assert what
is still assertable (the family resolves, the dumps run, the empty result is
well-formed, a nonexistent handle is a typed error, the `config` group resolves
and joins) and print `SKIPPED: …` and pass for the rest. **They never fail for
want of hardware.**

To get a real devlink device to test against, load the kernel's own simulator
(needs real root — `netdevsim` cannot be created from a user namespace):

```sh
sudo modprobe netdevsim
echo "1 2" | sudo tee /sys/bus/netdevsim/new_device
devlink dev show                       # netdevsim/netdevsim1
zig build test-devlink                 # the live tests now have something to talk to
echo "1" | sudo tee /sys/bus/netdevsim/del_device
```

Capture commands, the two iproute2 quirks the goldens pin, anonymisation and
the full deferred list are documented in `SPEC.md` and at the top of
`src/goldens.zig`.
