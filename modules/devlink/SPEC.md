# devlink — design, verification and deferred list

Auditor-facing companion to `README.md`. The `meta` block in
`src/root.zig` is authoritative for platform/role/concurrency/deps and is not
restated here.

## 1. What this module is

A client for the kernel's `devlink` generic-netlink family: the management
plane for network devices that are more than a netdev — SmartNICs and switch
ASICs, whose configuration (ports, driver parameters, on-chip resource
partitioning, firmware inventory, debug regions, health reporters, embedded
switch mode) has no rtnetlink or ethtool expression at all.

It sits on `genetlink` (which sits on `netlink`): the `genlmsghdr`, the nlctrl
family- and multicast-group resolution, the `NETLINK_GENERIC` socket, the
`MSG_PEEK|MSG_TRUNC` receive-sizing loop and `NETLINK_EXT_ACK` all come from
there. This module adds only devlink's commands, attributes and object model.

## 2. Design decisions

### 2.1 The handle is a value type, twice

`handle.Handle` borrows two slices and is the request-side type;
`handle.Owned` copies both into inline buffers and is the reply-side type. No
decoded object holds a pointer into the socket's receive buffer, so nothing
becomes dangling after the next `recvmsg`. `Owned.borrow()` converts back for a
follow-up request.

The inline caps (`bus_name_max` 16, `dev_name_max` 64, `name_max` 64,
`value_max` 128, `ifnamesize` 16) are this module's, not the UAPI's — devlink
declares no maxima for its strings. A reply that overruns one is
`error.BadLength`, **never** a truncation: a silently shortened device name is
a different device.

**`Handle.parse` vs `PortHandle.parse` — anchored against the real CLI, not
just self-consistent.** `Handle.parse` scans forward for one `/` and rejects a
second one (a port-suffixed string); `PortHandle.parse` scans backward for the
LAST `/` and requires the tail to be a valid port index. Whether this actually
matches what the `devlink` binary itself accepts and rejects for its own
`bus_name/dev_name` vs `bus_name/dev_name/port_index` forms was previously
`UNVERIFIED` — checked only against this module's own round trip. Verified
live against **iproute2 6.19.0's `devlink`** (same tool/version §4.1's byte-
exact goldens are captured from) on a hardware-less host — no real devlink
instance needs to exist for these; the CLI's own argument parser rejects a
malformed identification string BEFORE ever asking the kernel, distinguishably
from "kernel answers: No such device" (a real device lookup that reached the
kernel and failed):

| command | input | real CLI result |
|---|---|---|
| `devlink dev show` | `pci/0000:65:00.0` | format accepted (`kernel answers: No such device`) |
| `devlink dev show` | `pci/0000:65:00.0/3` | **format rejected**: `Wrong identification string format. Devlink identification ("bus_name/dev_name") expected` |
| `devlink dev show` | `nothing-here` (no `/`) | **format rejected**, same message |
| `devlink port show` | `pci/0000:65:00.0/3` | format accepted (`kernel answers: No such device`) |
| `devlink port show` | `pci/0000:65:00.0/x` | **format rejected**: `Port index "x" is not a number or not within range` |
| `devlink port show` | `pci/0000:65:00.0/3/4` | **format rejected**: `Wrong port identification string format. Expected "bus_name/dev_name/port_index" or "netdev_ifname"` |

This confirms the core claim this module's tests already pin (`handle.zig`'s
`"Handle.parse accepts bus/dev and refuses a port string"` and `"PortHandle.parse
splits off the trailing index"`): a device-only command's grammar is exactly
`bus/dev` (a port-suffixed string is rejected, matching `Handle.parse`'s inner-
`/` check) and a port command's grammar accepts the `bus/dev/index` triple with
a numeric tail (matching `PortHandle.parse`), with too many or non-numeric
segments rejected either way. `Handle.parse`/`PortHandle.parse` locally reject
some additional cases (e.g. an empty `bus`/`dev` component) that the real CLI's
own parser lets through to the kernel round trip instead of catching in its
argument parser — those are `validate()`'s own "reject locally what the kernel
would reject anyway" optimization (see its doc comment), not part of the
grammar boundary this anchor is about, and are not claimed to match the CLI's
parser byte-for-byte.

### 2.2 Every decoder is a pure function over bytes

`dev.parseDevice`, `dev.parseInfo`, `port.parse`, `param.parse`,
`resource.parse`, `region.parseRegion`, `region.Assembler.feed`, `health.parse`
and `eswitch.parse` take attribute slices and return values. No socket is
needed to test the wire format, which is what makes the hostile-input and fuzz
coverage cheap.

Likewise every request builder (`handle.append`, `port.appendSetType`,
`param.appendSet`, `region.appendRead`, …) appends attribute TLVs to a caller's
list; `client.zig` is the only place that prepends an `nlmsghdr`. That is what
lets `goldens.zig` reproduce iproute2's exact bytes including its unusual flag
choices.

### 2.3 Three decoders that are not table-driven

**Parameters.** `PARAM_VALUE_DATA` is `dynamic`; its width comes from
`PARAM_TYPE` in the same nest, and the kernel does not promise `PARAM_TYPE`
arrives first. `param.parseNest` therefore walks the nest twice: once for the
scalars (name, generic flag, type), once for `PARAM_VALUES_LIST`. A type the
module does not model yields `Value.unknown` with the raw payload rather than a
dropped value. On the way out, `appendSet` derives `PARAM_TYPE` from the
`Value` variant, so the two can never disagree.

**Resources.** `RESOURCE_LIST` is recursive with no bound on the wire.
`resource.parseList` carries `depth` explicitly against `max_depth = 8` and
decrements a shared `max_nodes = 1024` budget; both bounds are needed, because
depth alone does not bound memory (a flat list of 4-byte empty `RESOURCE` nests
expands to a full struct each). Ownership during the recursion is handled by
building each node's children *before* appending the node, with `freeNodes` (frees
what the nodes own) kept distinct from `freeChildren` (also frees the slice) so
an error path cannot double-free an `ArrayList`-owned buffer.

**Region reads.** `region.Assembler` places each `REGION_CHUNK` by address into
a caller-sized window and tracks a per-byte `seen` bitmap. Out-of-window and
overlapping chunks are `error.BadLength`; a chunk missing either `ADDR` or
`DATA` likewise. A *short* read is not an error — `Data.isComplete()` /
`Data.covered` report it — because a device returning less than was asked for
is legitimate.

### 2.4 The blocking seam

Command methods are ordinary blocking request/reply calls. `EventSocket` has
exactly one blocking call, `waitForNotification`, doing one `recvmsg` when its
buffer is drained; `fd()` is exposed for the caller's own poll loop. No timer
thread, no deadline, no event loop — the same discipline as `ethtool`,
`nl80211`, `netconf` and `ebpf`.

### 2.5 No second extended-ACK buffer

`lastErrorMessage` reads the shared `netlink.Socket` extended-ACK buffer that
`genetlink.Socket` already carries; `client.noteErrorMessage` writes into it.
The module keeps no private copy. (`netlink.Socket.captureExtAck` is not
reachable through the `genetlink` facade, which is the only reason the four
lines exist at all.)

### 2.6 Dumps filter client-side

devlink's dump handlers walk every registered instance regardless of the
attributes in the request. `ports`/`params`/`regions`/`healthReporters`
therefore take an *optional* handle and filter after decoding — which is what
the `devlink` binary does. The single-object forms are real `doit` requests.

## 3. Threat model

The kernel is the only peer, but the *messages* are treated as untrusted:
devlink replies also arrive over a multicast group any process on the system
can send to if it can bind the group, and a driver bug is indistinguishable
from malice at this layer.

| input | handling |
|---|---|
| truncated / overlong TLV | `netlink.codec`'s bounds-checked walkers → `error.Truncated` / `error.BadLength` |
| wrong-width integer attribute | exact-width guards (`asU8`/`asU16`/`asU32`/`uapi.asU64`) — a u32 read as u64 is an error, never a wild read |
| string longer than the inline buffer | `uapi.copyName` → `error.BadLength`, never a truncated name |
| unbounded `RESOURCE_LIST` nesting | `max_depth` → `error.TooDeep` (2000-level stream is a committed test) |
| wide `RESOURCE_LIST` | `max_nodes` → `error.TooManyResources` |
| oversized `PARAM_VALUES_LIST` | `max_values` (16) → `error.BadLength` |
| oversized snapshot list | `max_snapshots` (64) → `error.BadLength` |
| region read window | `max_read_len` (16 MiB) and an overflow check on `address + length`, both before allocation |
| region chunk outside the window | `error.BadLength` |
| region chunk overlapping another | per-byte `seen` bitmap → `error.BadLength` |
| unknown enum value | non-exhaustive enums (`_`) — round-trips instead of being illegal behaviour |
| unknown attribute | ignored |
| stray datagram | `(portid, seq)` matching in `client.Walk`; the event socket filters on the family id |
| `NLMSG_OVERRUN` | `error.SystemResources` — the caller must resynchronise |

Requests are validated locally where the kernel would answer `EINVAL` anyway
(empty or over-long handle/parameter/region/reporter names, embedded NULs, a
`PORT_SPLIT` count below 2, `PortType.notset`, an empty `ESWITCH_SET`, a
zero-length region read), so those are `error.InvalidRequest` without a round
trip.

Fuzz targets (`std.testing.fuzz`): device + info decode, port decode, parameter
decode, resource decode, region decode + chunk reassembly, health decode,
notification parse — seven in total.

## 4. Verification

### 4.1 Byte-exact request goldens — real captures

Captured from **iproute2 6.19.0's `devlink`** on Linux 7.0:

```sh
strace -f -e trace=%network -e write=all -e read=all -s 64 -o log.txt devlink <args>
```

`-e trace=%network` rather than a `sendmsg` filter, because **`devlink` sends
with `sendto`** — the same trap that made an early `ethtool` capture attempt
come back empty. The capture was checked to be non-empty before anything was
written down.

Commands captured (each with its exact command line in a comment beside the
golden in `src/goldens.zig`):

| command | pins |
|---|---|
| `devlink dev show` | `CMD.GET` dump, `REQUEST\|ACK\|DUMP` |
| `devlink port show` | `CMD.PORT_GET` dump |
| `devlink dev param show` | `CMD.PARAM_GET` dump |
| `devlink region show` | `CMD.REGION_GET` dump |
| `devlink health show` | `CMD.HEALTH_REPORTER_GET` dump |
| `devlink dev info` | `CMD.INFO_GET` dump |
| `devlink dev show <handle>` | `BUS_NAME` + `DEV_NAME` order and encoding |
| `devlink port show <handle>/1` | `+ PORT_INDEX` |
| `devlink dev info <handle>` | doit form |
| `devlink dev eswitch show <handle>` | `CMD.ESWITCH_GET` = 29 |
| `devlink dev param show <handle> name X` | `PARAM_NAME` = 0x51 |
| `devlink region show <handle>/cr-space` | `REGION_NAME` = 0x58 |
| `devlink health show <handle> reporter fw` | `HEALTH_REPORTER_NAME` = 0x73 |
| `devlink resource set <handle> path kvd/linear size N` | `CMD.RESOURCE_DUMP` = 36, **ACK-less** |
| `devlink port set <handle>/1 type eth` | `PORT_TYPE` u16 |
| `devlink port split <handle>/1 count 2` | `PORT_SPLIT_COUNT` u32 |
| `devlink port unsplit <handle>/1` | port handle alone |
| `devlink dev param set … cmode runtime/driverinit/permanent` | `PARAM_VALUE_CMODE` u8, all three values |
| `devlink region new <handle>/cr-space snapshot 5` | `REGION_SNAPSHOT_ID` u32 |
| `devlink region del <handle>/cr-space snapshot 5` | `CMD.REGION_DEL` = 45 |
| `devlink region read … address 0 length 16` | `CHUNK_ADDR`/`CHUNK_LEN` **u64**, and `NLM_F_DUMP` |
| `devlink health recover <handle> reporter fw` | `CMD.HEALTH_REPORTER_RECOVER` = 54 |
| `devlink dev eswitch set … mode … inline-mode … encap-mode …` | the u16/u8/u8 width asymmetry |

Every SET-form capture was made against a handle that does not exist and was
refused with `ENODEV`/`EPERM` — **after** the bytes were already on the wire,
which is why they are as real as they would be against a switch.

Two iproute2 quirks are pinned rather than normalised:

1. **`devlink dev param set` sends `PARAM_GET` first**, to learn the
   parameter's type, and only then the typed `PARAM_SET`. Without a real device
   the `PARAM_GET` fails and the `SET` is never emitted, so what was captured
   is that type-discovery `PARAM_GET` carrying the requested cmode. The three
   captures with `value 10`, `value true` and `value hello` are byte-identical
   apart from the cmode byte — which is itself the evidence that the value had
   not yet been typed. **`PARAM_SET`'s own request bytes are therefore
   UAPI-derived**, not captured; the ordering used (`NAME`, `TYPE`,
   `VALUE_CMODE`, `VALUE_DATA`) is asserted only against the module's own
   round-trip test.
2. **`devlink health recover` emits the handle and reporter name twice** in one
   message. Netlink policy parsing takes the last occurrence, so the kernel is
   unaffected. The capture is reproduced exactly (by calling the builder
   twice); this module's own request emits them once, and the golden asserts
   the one-copy form is a prefix of the captured one.

### 4.2 Reply goldens

**Real kernel bytes** (four):

- the nlctrl `CTRL_CMD_NEWFAMILY` reply for `devlink`, 1236 bytes — proves
  family-id resolution (25/0x19) and the shared
  `genetlink.findMcastGroupId` against the real `config` group (id 11), and its
  `CTRL_ATTR_OPS` table is cross-checked against every command constant this
  module sends (57 ops);
- the `NLMSG_DONE` that terminates an empty `dev show` dump;
- an `NLMSG_ERROR` carrying `-ENODEV`;
- an `NLMSG_ERROR` carrying `-EPERM` (from the privileged `ESWITCH_GET`).

**Captured from a real device (2026-08-08, wave-2 F1)** — all eight object
replies: the device reply, the two-port dump, the parameter dump (a generic
`u32` and a driver-specific flag), the recursive resource tree, the region
reply with a snapshot, the `REGION_READ` chunk, the health-reporter dump and
the `INFO_GET` reply. They came from a live `netdevsim` instance running as
real root inside the repo's VM lane, and iproute2 6.19.0's own `devlink`
decoded the same replies in the same run — its transcript is quoted at each
test and is the oracle the assertions are read from.

`netdevsim.ko` is shipped by no Debian and no OpenWRT package (Debian does not
set `CONFIG_NETDEVSIM` in either its cloud or its generic kernel), so it was
built from the kernel's own sources out of tree against the guest's kernel
headers, inside a throwaway `-snapshot` guest. Full recipe in
`src/goldens.zig`'s "captured replies" header. Nothing in the committed tests
needs a VM, a kernel module or any privilege to run.

**Still UAPI-derived, and kept for exactly that reason:** the constructed
replies covering shapes `netdevsim` does not have — VF representor ports, a
parameter with all three cmodes, a tripped health reporter, a pending firmware
update, a multi-message chunked `REGION_READ` arriving out of order. Those are
labelled as constructed in the file and were not removed when the captures
landed.

**What the captures found.** Two structural facts that had been asserted only
against ourselves turned out to be different from what the constructed goldens
assumed, and both are now pinned:

1. A **param** dump is answered with `DEVLINK_CMD_PARAM_GET` (38), and a
   **region** dump with `REGION_GET` (42) — *not* with `PARAM_NEW` (40) /
   `REGION_NEW` (44), which is the pattern the device and port dumps follow
   (`NEW`, `PORT_NEW`) and which the constructed goldens used. Harmless today,
   because `client.params`/`regions` parse every message in the dump rather
   than filtering on the reply command — but a future "tighten the dump loop by
   checking the command" change would have silently returned nothing on real
   hardware.
2. `INFO_DRIVER_NAME` arrives **after** the version nests, not before.

### 4.3 Anonymisation

- **`nlmsg_pid` was zeroed in every captured reply.** It is the capturing
  process's netlink port id, derived from its pid. These goldens are decoded,
  not matched against a live socket, so zeroing it changes no assertion. This
  is a length-preserving substitution.
- **The handle in every request capture is `pci/0000:00:00.0`** — the x86 host
  bridge. It exists on every such machine, is not a network device, and carries
  no identity. It was chosen deliberately so that no real device's bus address
  appears in the repository.
- **Constructed replies use `pci/0000:65:00.0`**, a plausible but fictitious
  address, and invented serial numbers (`XX0000XX0000`), PSIDs
  (`XX_0000000000`) and firmware versions (`0.0.1000`/`0.0.1001`). **No real
  board identifier, serial number or PCI address of any device on the capture
  machine appears anywhere in this module.**

Nothing else was altered: lengths, offsets, padding and every attribute of the
captured bytes are exactly as `devlink` and the kernel produced them.

### 4.4 Live tests

`src/root.zig` runs real requests against this machine's kernel. Nothing writes
— no SET, SPLIT, SNAPSHOT or RECOVER is issued even when privileged, because
devlink writes reset hardware.

What runs on a machine with no devlink device (the capture machine, and the
common case):

- the family resolves to a dynamic id above `GENL_ID_CTRL`;
- `CMD.GET`, `PORT_GET`, `PARAM_GET`, `REGION_GET`, `HEALTH_REPORTER_GET` and a
  raw `RATE_GET` dump all round-trip and return empty;
- `INFO_GET` and `ESWITCH_GET` against a nonexistent handle return typed errors
  (`NoSuchDevice` / `AccessDenied`) rather than hanging or panicking;
- locally-invalid requests are refused before reaching the kernel;
- the `config` multicast group resolves to a nonzero id and can be joined, and
  a nonexistent group is `GroupNotFound`;
- the shared transport seam works: `handle()`, `portid`, `setRecvTimeout` with
  a `WouldBlock` on an idle socket, and the socket still usable afterwards.

Everything that needs a real instance prints `SKIPPED: …` and passes. **No live
test can fail for want of hardware.**

## 5. Deferred — and why

Everything below is reachable through `Devlink.raw`; none of it is blocked by a
design decision here.

| deferred | why |
|---|---|
| **rate objects** (`RATE_GET`/`SET`/`NEW`/`DEL`) | Only meaningful on an eswitch with VF/SF rate limiting; a full model needs the leaf/node tree and the TC bandwidth nest. Sizeable and unverifiable without hardware. |
| **traps, trap groups, trap policers** | Three related object families with their own statistics nests; mlxsw-specific in practice. Large enough to be its own increment. |
| **DPIPE** (`DPIPE_TABLE_GET`, `ENTRIES_GET`, `HEADERS_GET`) | A whole pipeline-introspection schema — headers, fields, matches, actions, entries — nested five deep. Bigger than the rest of devlink combined, and only mlxsw implements it. |
| **shared buffers** (`SB_*`, 20 commands) | Pool/port-pool/TC-bind matrix plus occupancy snapshots. Coherent as a unit, and none of it is testable without a switch ASIC. |
| **flash update** | Needs a firmware file on disk and emits an asynchronous progress stream on the `config` group (`FLASH_UPDATE_STATUS`). The write half is dangerous to expose without a way to exercise it. |
| **selftests** | `SELFTESTS_GET`/`RUN`; running one takes the device down. |
| **linecards** | Modular-chassis only; carries a `NESTED_DEVLINK` handle whose semantics deserve their own treatment. |
| **`RELOAD`** | Re-instantiates the driver and can move the instance into another netns (`NETNS_FD`/`PID`/`ID`). Genuinely destructive; deferred until there is a device to prove it against. |
| **port functions** (`PORT_FUNCTION` nest) | Hardware address, admin state, capability bitfield and max-IO-EQs for SF/VF ports. The port decoder reports the nest's *presence* (`Port.has_function`) but does not decode it. |
| **`PORT_NEW`/`PORT_DEL`** | Subfunction lifecycle; pairs with port functions. |
| **health diagnose / dump** (`HEALTH_REPORTER_DIAGNOSE`, `DUMP_GET`, `DUMP_CLEAR`, `TEST`) | Their payload is the `DEVLINK_ATTR_FMSG` nest — a self-describing, recursively typed object/array format that is its own decoder. `HEALTH_REPORTER_SET` is deferred with them. |
| **`DEV_STATS` / `RELOAD_STATS`** | Per-action, per-limit reload counters. `Device.has_reload_stats` reports the nest's presence only. |
| **`NOTIFY_FILTER_SET`** | Narrows what a multicast subscriber receives; useful, but only once there is something to receive. |
| **`PORT_PARAM_GET`/`SET`** | Per-port parameters. The decoders already handle a `PORT_INDEX` on a parameter; only the commands are missing. |

## 6. Backlog

1. ~~**Verify against `netdevsim`.**~~ **DONE 2026-08-08** — see §4.2. All
   eight object replies are now real captures from a live `netdevsim` in the
   VM lane. What is *not* yet captured from it: a **tripped** health reporter
   (`HEALTH_REPORTER_TEST` trips `dummy` on demand) and a notification on the
   `config` group; both are reachable with the same recipe.
2. **`PARAM_SET` request golden.** iproute2 will not emit one without a device
   (§4.1 quirk 1), and `netdevsim` now supplies one — reachable with the same
   recipe, in the same guest, and no longer blocked.
3. **A notification golden.** Same: `devlink monitor` prints, and nothing on
   this machine ever emits on the `config` group.
4. **Port functions**, then **rate objects** — the two deferred items with the
   clearest standalone value for an SR-IOV/SF fleet agent.
5. **FMSG decoder**, which unlocks health diagnose/dump in one step.
