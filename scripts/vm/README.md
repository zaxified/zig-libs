# scripts/vm/ — real-root test lane

Three test gaps survive on a normal dev host no matter how `scripts/test.sh`
wraps things:

- **tc's `RTM_NEWACTION`** (`tc actions add|del|get`, the shared action
  table) checks `CAP_NET_ADMIN` against the **initial** user namespace
  (`act_api.c`'s `tc_ctl_action` calls `netlink_capable`, not
  `netlink_net_capable`). `unshare -rn` — an unprivileged user+net namespace
  — cannot grant that; neither can a rootless container. Nothing short of
  real root does.
- **Other netlink/nftables/wireguard live writes** work fine under
  `unshare -rn`, but a namespace only isolates the writes from the *host*'s
  own netlink state — it doesn't give you a second machine, so two runs (or
  a run racing something else on your desktop) can still collide.
- **eBPF verifier acceptance** needs `CAP_BPF`.

Inside a VM you're just root, on a throwaway machine, and `-snapshot` makes
every boot disposable. This lane exists for exactly those three gaps — it is
**opt-in only** (`scripts/test.sh vm ...`), never part of `changed`/`all`,
because booting a VM (~20-30s) would wreck the fast edit/test loop those
exist for.

## Quick start

```
scripts/vm/fetch-images.sh          # one-time, ~570 MB of upstream artifacts
scripts/vm/provision.sh             # one-time, ~3 min — see "Provisioning" below
scripts/test.sh vm tc               # or: scripts/vm/run.sh tc debian
scripts/vm/run.sh tc openwrt        # now works too — see "Provisioning"
```

`fetch-images.sh` downloads and checksum-verifies **upstream** artifacts.
`provision.sh` turns them into guests that actually have this repo's
prerequisites installed (OpenWRT gains `tc` + the sched/netem kmods; Debian
gains `bpftool` & friends). Both are idempotent: re-running them is a no-op
unless a package list in `manifest.sh` changed.

## What actually works — verified, not assumed

The brief handed to build this assumed OpenWRT would cover the tc gap and
that Debian's "nocloud" cloud image needed no seeding. Both assumptions were
wrong; here's what's actually true, checked by booting real VMs and running
real test binaries in them (not by reading docs):

- **OpenWRT's *stock* x86-64 build has no `tc` support at all.** No `tc`
  binary, and none of `sch_netem`/`sch_htb`/`sch_tbf`/`act_gact`/`cls_u32`/
  `cls_flower` load (`modprobe` reports "not found" for every one) — this is
  a genuine package/kernel-config gap, not a privilege wall. It is **fixed by
  provisioning** (see below): the ImageBuilder-built image has `tc` 6.18.0 and
  loads every one of those. Debian, whose generic cloud kernel (6.12.96) has
  them all built or packaged already and ships `tc`/iproute2 6.15, stays the
  default route for `tc` because it needs no build step.
- **OpenWRT *does* have nftables** (`nft` binary present, `nf_tables.ko` +
  the `nft_ct`/`nft_fib`/`nft_nat`/`nft_masq`/`nft_reject`/… companion
  modules). `scripts/vm/run.sh nftables openwrt` execution-verifies this:
  73 tests pass, including a live create/list/delete round-trip, a
  batch-rollback-on-failure case, and JSON⇄native consistency. Same for
  `conntrack` (28 tests, `nf_conntrack.ko` + defrag modules present).
- **OpenWRT has no BPF tooling** (no `bpftool`, no `/proc/config.gz` to even
  check `CONFIG_BPF`). Route eBPF/XDP work to Debian; this was not
  execution-verified either way (no eBPF module test exists yet) — flagged
  as a gap, not silently assumed to work.
- **Debian's "nocloud" image is NOT unattended.** "nocloud" only means "no
  cloud-init datasource" — booted with nothing else, it hangs forever at an
  interactive `systemd-firstboot` wizard ("Please enter the new timezone
  name...", waiting on a TTY that will never answer). Fixed via QEMU
  **fw_cfg-injected systemd credentials** (`passwd.hashed-password.root`,
  `firstboot.locale`, `firstboot.timezone`, `firstboot.keymap`) — this is
  boot-time credential injection, not image seeding: the qcow2 on disk is
  never touched, and `-snapshot` discards the ephemeral in-VM writes on
  poweroff too. (SMBIOS type-11 OEM strings — the more commonly-documented
  mechanism — were tried first and were flaky: one credential would
  sometimes silently fail to land, leaving the wizard stuck on one question.
  fw_cfg's file-backed transfer didn't have that problem.)
- **A cross-compiled Zig test binary needs `-cpu host`, not just default
  KVM accel.** Both the musl (OpenWRT) and glibc (Debian) test binaries died
  with `Illegal instruction` on their very first instruction under QEMU's
  default CPU model. Isolated with `qemu-x86_64` (user-mode emulation,
  which ran the same binary fine) and by running the same binary directly
  on the host (also fine) — the fault is specific to full-system QEMU's
  default CPU model missing something Zig assumes even at its conservative
  "baseline" target-CPU setting. `-machine accel=kvm:tcg -cpu host` (real
  hardware pass-through) fixes it outright.
- **`-snapshot` is sufficient — nothing observed leaking.** Every run here
  used the same two image files repeatedly across dozens of boots; the
  files' sizes and checksums are unchanged after all of them. `-snapshot`
  writes VM disk changes to a temporary overlay that's discarded on exit;
  the only thing that persists is whatever's inside the guest's own RAM
  during the run, which vanishes at poweroff.

## Platform routing

| Module | Platform | Status |
|---|---|---|
| `tc` | debian (default) **or openwrt** | both execution-verified, **130/130 on each** since the action-table bug this lane found was fixed (see "A real bug this lane found"). openwrt needs `provision.sh` first; that's the only reason debian stays the default |
| `nftables` | openwrt | execution-verified (73 tests incl. live round-trip) |
| `conntrack` | openwrt | execution-verified (28 tests) |
| `ebpf` | debian | execution-verified, **137/137**. Six live attach tests (kprobe, uprobe, tracepoint, raw tracepoint, cgroup link) need `CAP_BPF` + `CAP_PERFMON` and skip on any normal host; OpenWRT's kernel has no BPF tooling at all, so this one is debian-only |
| `fleetsim` | debian | execution-verified. **Not a privilege gap — a *counterpart* gap** (see below): **five** real masters drive five simulated devices in one boot — pymodbus 3.14.0 (Modbus), pycomm3 1.2.16 (EtherNet/IP), bacpypes3 0.0.106 (BACnet), python-snap7 3.1.0 (S7comm), asyncua 2.0.1 (OPC UA) — each grading what it decoded and commanding its marks back into the device. ~5m20s (the live tests run one after another, each holding its socket for a 60 s budget) |
| everything else | debian (default) | most NETNS_MODULES don't need this lane at all — `unshare -rn` already covers them (see `scripts/test.sh`'s own `NETNS_MODULES` comment); route here only for isolation, not privilege |

Override with `scripts/vm/run.sh <module> openwrt|debian` when the default
routing is wrong for your case. The table lives in `scripts/vm/run.sh`
(`route_platform`), not duplicated here, so there's one place to update.

## Provisioning: giving a guest what the stock image lacks

The stock OpenWRT image has no `tc` at all (see above) — no binary, no
`sch_netem`/`sch_htb`/`sch_tbf`/`act_gact`/`cls_u32`/`cls_flower` kernel
modules. `scripts/vm/provision.sh` closes gaps like that **declaratively**:
edit a package list in `scripts/vm/manifest.sh`, run the script, get a guest
that has the prerequisite. Nothing about `run.sh`'s own flow changes.

**One mechanism per platform, both unprivileged, no sudo, nothing written
outside `scripts/vm/`:**

- **OpenWRT → the official ImageBuilder.** Downloaded and checksum-verified
  exactly like the stock image (`scripts/vm/fetch-images.sh imagebuilder`),
  then `make image PROFILE=generic PACKAGES="..."` builds a brand-new image
  from scratch out of the declarative list. ImageBuilder is self-contained
  (own toolchain under `staging_dir/host/bin`, own `apk` implementation) and
  runs as a normal user — no kernel recompile, no loop mounts.
- **Debian → boot + apt + commit.** `provision.sh` copies the verified stock
  qcow2, boots that copy **without `-snapshot`** (`provision-debian.exp`,
  a sibling of `boot-debian.exp` that reuses its login/firstboot dance and
  marker convention but keeps disk writes instead of discarding them), runs
  `apt-get update && apt-get install` for the declared list over the same
  console `boot-debian.exp` already uses, `sync`s, and powers off. The
  resulting qcow2 is the new provisioned base; ordinary `run.sh` runs then
  layer their own `-snapshot` on top of it exactly as they do on the stock
  image today. Deliberately NOT libguestfs/virt-customize: that needs
  `/boot/vmlinuz-*` readable, which is root-only on this host, and widening
  that is out of scope.

**Two-stage trust** (full rationale in `scripts/vm/manifest.sh` and
`scripts/vm/recipe.sh`): fetching an image is a real supply-chain guarantee —
somebody upstream published a checksum, `fetch-images.sh` verifies it, a
mismatch aborts loudly. The moment `provision.sh` *changes* that image, that
guarantee stops applying to the result: the derived image's own SHA-256 is a
fact about this machine's build, not a signature from anyone, and writing it
down as if it were an upstream checksum would misrepresent where the trust
comes from. What **is** reproducible is the *recipe* — upstream artifact
checksum + package list + platform + a hand-bumped procedure version — and
that tuple is what gets hashed and baked into the provisioned image's
filename (`openwrt-...-prov-<hash>.img`, `debian-...-prov-<hash>.qcow2`).
Each image carries a `.provenance` sidecar with the full recipe text in the
clear and one clearly-labelled `derived-sha256:` line for change detection
only — never presented as an upstream guarantee.

**Caching by recipe hash, not by convention.** Because the hash is IN the
filename, a package-list edit makes the current recipe resolve to a name
that doesn't exist yet — a guaranteed cache miss, never a stale hit. `run.sh`
looks for that exact name; if it's not there it falls back to the stock
image with a loud warning (naming any stale provisioned images left over
from an older recipe, so "wrong image" and "the package didn't install"
never look like the same failure).

Demonstrated live on both mechanisms:

- **OpenWRT**: adding `kmod-sched-cake` moved `recipe-sha256` from
  `86cf4482d2f0…` to `43f8fc41e153…`, `provision.sh --recipe openwrt`
  flipped to `cached: NO (would rebuild)`, `run.sh tc openwrt` refused the
  `86cf…` image by name and said so on stderr, and `provision.sh openwrt`
  rebuilt (1m57s, 9 packages in the manifest instead of 8). Reverting the
  one-line edit put the hash back to `86cf4482d2f0…` and `provision.sh
  openwrt` returned in **50 ms** — cache hit, no rebuild, with the
  now-orphaned `43f8…` image listed as safe to delete.
- **Debian**: adding `moreutils` moved `recipe-sha256` from `0deab535a92e…`
  to `1ba61b765ad9…`, `--recipe debian` flipped to `cached: NO`, and
  `provision.sh debian` rebuilt in 1m14s (fresh copy + boot + apt-get
  update/install + poweroff). Reverting put the hash back to
  `0deab535a92e…` and `provision.sh debian` returned in **52 ms** — cache
  hit, the `1ba6…` image named as safe to delete.

`scripts/vm/provision.sh --recipe [openwrt|debian]` prints the exact recipe
text, its hash, the image path it resolves to, and whether that's cached —
without building anything. Useful for checking "would this run.sh invocation
rebuild?" before committing to a 2-3 minute wait.

### OpenWRT package list (verified against the ImageBuilder's own index, not guessed)

| Package | What it provides | Why |
|---|---|---|
| `tc-full` | userspace `tc` (iproute2 6.18.0) | OpenWRT splits tc into tc-tiny/tc-full/tc-bpf; tc-full is the one with the complete qdisc/filter/action set and already depends on kmod-sched-core |
| `kmod-sched-core` | `sch_htb`, `sch_tbf`, `sch_hfsc`, `sch_ingress`, `cls_u32`, `act_gact`, `act_mirred`, `act_skbedit`, `cls_basic/flow/fw/route/matchall`, `em_u32` | one bundle, not one kmod per qdisc — so most of what the tc suite needs arrives here |
| `kmod-sched` | `sch_codel`, `sch_fq`, `sch_gred`, ... | `kmod-netem`'s own declared dependency |
| `kmod-netem` | `sch_netem` | its own top-level package, NOT under the `kmod-sched-*` namespace |
| `kmod-sched-flower` | `cls_flower` | separate package, own .ko |
| `kmod-sched-act-police` | `act_police` | the tc suite's "filter action list" test chains a u32 filter into a policer action; not part of sched-core |
| `kmod-ifb` | `ifb.ko` | future S2 edge-shaper work |
| `kmod-veth` | `veth.ko` | netns-style topologies |

How those names were established — three checks, no guessing:

1. **The index.** `apk adbdump packages.adb` (using the ImageBuilder's own
   `staging_dir/host/bin/apk`) over the repositories listed in the
   ImageBuilder's `repositories` file. That is where `tc-full` vs `tc-tiny`
   vs `tc-bpf` came from, and where `kmod-netem` turned up as a top-level
   package rather than a `kmod-sched-*` one.
2. **The payloads.** `apk adbdump <pkg>.apk` lists the `.ko` files each
   package actually installs — so "kmod-sched-core contains `sch_htb`" is
   read off the artifact, not inferred from a description string. This is
   what showed `act_police` is *not* in sched-core and needs its own
   package, which no amount of `kmod-sched*` pattern-matching would have.
3. **The build manifest.** After `make image`, `provision.sh` greps the
   ImageBuilder's own `.manifest` and **fails loudly** if any requested
   package is missing — ImageBuilder otherwise only warns on an unknown name
   and keeps going, which would ship a "successful" image missing exactly
   the thing that was just added.

Then execution-verified in the booted guest: `which tc` → `/sbin/tc`,
`tc -V` → `iproute2-6.18.0`, and `modprobe` succeeds for all of
`sch_netem sch_htb sch_tbf act_gact act_police act_mirred act_skbedit
cls_u32 cls_flower sch_fq_codel ifb veth`.

### Debian package list

| Package | Already on stock image? | Why declared anyway |
|---|---|---|
| `iproute2`, `ethtool` | yes | declares the guarantee explicitly rather than assuming it (apt makes it a no-op) |
| `kmod`, `bpftool` | **no** (verified: absent on stock) | future eBPF/module-probing test needs |
| `python3`, `python3-pip` | pip: **no** | the interpreter and installer for `VM_DEBIAN_PIP`; every SCADA master `fleetsim`'s live lane needs is a pip-only library |

### Debian pip list (`VM_DEBIAN_PIP`)

| Spec | Why |
|---|---|
| `pymodbus==3.14.0` | the Modbus master `fleetsim`'s live Modbus test is written against. `python3-pymodbus` in trixie is 3.8.6 — years behind, and a master's own defaults are part of the oracle, so the version is pinned rather than floated. BSD-3-Clause; read off the installed distribution's metadata at capture time and recorded in the root `NOTICE`, not quoted from memory |
| `pycomm3==1.2.16` | the EtherNet/IP master. MIT. Note its single-tag `write()` puts the request on the wire twice, which is why every write below is issued as a pair; documented in `guests/fleetsim-enip-master.py`. That file also overrides `_initialize_driver` to supply the tag table — no longer *necessary* since `modules/enip` gained the Program Name and Symbol objects, but kept deliberately, because changing it would re-cut the frozen session in `modules/fleetsim/src/master_goldens.zig` |
| `bacpypes3==0.0.106` | the BACnet client. MIT. Its protocol errors derive from `BaseException`, which is worth knowing before writing anything against it |
| `python-snap7==3.1.0` | the S7 client. MIT, and **pure Python** from 3.x — it speaks TPKT/COTP/S7 over an ordinary socket, so no `libsnap7` apt package is needed or installed. Verified, not assumed: the wheel is `py3-none-any` and the client connects with no `lib_location` |
| `asyncua==2.0.1` | the OPC UA client. **LGPL-3.0-or-later** — the only non-permissive entry here. Run as a separate process in a disposable guest; nothing is linked against it and nothing of it is redistributed. Reasoning recorded in `modules/fleetsim/SPEC.md` |

Pinning is enforced, not documented: `provision.sh` refuses a spec without
`==` before booting, and the guest greps each spec back out of `pip freeze`
with `-Fxq` so an image whose contents disagree with its own recipe hash never
gets written.

## A fourth reason to use this lane: a counterpart you may not install

The three gaps at the top of this file are all about *privilege*. `fleetsim`
found a fourth that has nothing to do with root: a test needs a **third-party
counterpart process** that is not allowed on the dev host. Its eight `test
"live: …"` cases each need a real SCADA master (pymodbus, pycomm3, bacpypes3,
python-snap7, asyncua, c104, opendnp3), every one of them pip-only or a C++
build, and the standing rule here is that a host venv is one-shot and
persistent counterparts must be system-installed by whoever runs them. So the
module's only external anchor never ran, and a green `test-fleetsim` certified
zero third-party interop.

Inside a disposable guest that constraint evaporates: `apt` and `pip` may do
whatever they like, `-snapshot` throws the result away, and the host stays
clean. Three small pieces make it work, all of them general rather than
fleetsim-specific:

- **`VM_DEBIAN_PIP` in `manifest.sh`** — a declarative pip list installed in
  the same provisioning boot as apt, and hashed into the recipe exactly like
  the apt list, so the image's contents and its filename cannot drift apart.
  Every spec must be `name==version`; `provision.sh` refuses an unpinned one
  before booting, and the guest re-reads each spec back out of `pip freeze`
  with an exact match so "pip resolved a different version" fails the build
  instead of silently shipping.
- **`guest_files` / `guest_setup` / `guest_after` in `run.sh`** — extra files
  served over the same one-off http server the test binary arrives on, a
  command batch that runs before the binary (start the counterpart, export the
  endpoint) and one that runs after it (collect the counterpart's log). The
  counterpart retries its connect, so which process wins the start race is not
  load-bearing.
- **`guest_require` in `run.sh`** — markers the guest must print for the run to
  count. This is the important one, and the next section says why.

### The counterpart has to *grade*, not merely exist

Measured, not assumed. Byte-swapping the register encoder in
`modules/modbus/src/server.zig` (`.big` → `.little` in the read-registers
reply) and re-running this lane gave **`GUEST_EXIT=0`** — the live test itself
*passed* with every register value wrong. It asserted only `delivered > 0` and
`replied > 0`; a wrong answer is still an answer and still gets counted. The
run went red solely because pymodbus decoded 28416 where 111 was expected, said
`MODBUS_MASTER_FAIL`, and `guest_require` did not find its marker.

So: **a live counterpart whose verdict nobody reads is a liveness check wearing
an anchor's clothes** — and a grade enforced by a shell `grep` is not a test
suite either. The arrangement that replaced it, and the one to copy:

1. the counterpart **grades** what it decoded, in its own number domain;
2. it **commands its marks back into the device** through that protocol's own
   write service (Modbus FC 0x10/0x05, CIP `Write Tag`, BACnet `WriteProperty`,
   an S7 DB write, the OPC UA `Write` service);
3. the module's **test** asserts on those marks, against constants recomputed
   from the fixture;
4. `guest_require` is demoted to **presence** (`*_MASTER_DONE`) — the one job a
   shell gate is actually good at.

Marks must be sums, differences, bitmaps, checksums, scaled integers or error
codes the counterpart itself named — **never an echo of the decoded value**. An
echo is the inverse of the read, so a device whose encoder and decoder share
the same wrong convention round-trips it cleanly and the fault hides inside it.
All five masters here were held to that bar by injecting a wrong value into
their adapter and checking the **test** went red with the presence marker still
printed; the four measurements are tabulated in `modules/fleetsim/SPEC.md`.

### And freeze what the live run said

A live test that only runs in a VM nobody spins up is barely better than a
skip. Every `scripts/vm/guests/fleetsim-*-master.py` therefore drives its device
through a byte tap and prints the whole session — every request and response
frame, plus what the master decoded — between `FLEETSIM_CAPTURE_BEGIN`/`END`
markers. Those bytes are frozen into `modules/fleetsim/src/master_goldens.zig`,
which replays them offline on every build, never skips, and needs no VM. The
taps are plain socket relays rather than the libraries' debug logging, so a
capture depends on no library internal and records what actually crossed the
wire; each reassembles frames from the protocol's own length field, so the
vectors are frames rather than TCP segments.

**One protocol cannot be frozen, and saying so is part of the method.** An OPC
UA session is established with material the *server* mints — a nonce, a session
id, an authentication token — and every later request carries the token it was
handed, so a recorded ReadRequest cannot be replayed against a freshly
constructed server. There is no byte-exact offline replay of a UA session, and
none is claimed: the asyncua transcript is graded live and recorded in prose.
Freezing something that merely looked like a corpus would have been worse than
the gap.

## Adding a module to the VM lane

Nothing to register. `scripts/vm/run.sh <module>` reads the same
`zig build module-graph` TSV `scripts/test.sh` does, resolves `<module>`'s
own dependency closure (what it imports, transitively — the opposite
direction from `test.sh`'s reverse-dependency closure), and cross-compiles
that closure with `zig test --dep ... -M... --test-no-exec` — the same
per-module dependency wiring `build.zig` does, just assembled on the
command line instead of read from it, so no module needs any VM-specific
plumbing. If the module isn't in `route_platform`'s table it defaults to
Debian; add a row there once you know which platform actually serves it
(and whether that's execution-verified or a guess — say which).

## How a run works

1. `zig build module-graph` gives the dependency closure.
2. `zig test --test-no-exec -femit-bin=...` cross-compiles
   (`x86_64-linux-musl` for OpenWRT, `x86_64-linux-gnu` for Debian) —
   **without running the binary on the host.** This is deliberately not
   `zig build test-<module> -Dtarget=...`: that step always chains an
   `addRunArtifact`, which would execute the cross binary the moment its
   OS/arch matched the host (a static musl binary runs fine on a glibc
   host — same kernel, no dynamic linking needed — so it wouldn't even
   fail loudly, just quietly test the wrong thing).
3. Boot the image with `-snapshot -cpu host`.
4. Get the binary into the guest: qemu's usermode netdev tftp server
   (`-netdev user,tftp=<dir>`) needs no host-side server process at all, but
   neither image actually has a tftp client (checked: OpenWRT's busybox has
   no `tftp` applet built in; Debian nocloud has neither `tftp` nor
   `busybox`) — so both fall back to a one-off `python3 -m http.server`
   (OpenWRT: `wget`; Debian: `curl`, its only transfer tool).
5. Run it as root; capture stdout and the real exit code via a
   `GUEST_EXIT=$?` marker.
6. `scripts/vm/run.sh` exits with that same code. **This is load-bearing**:
   a harness that always reports success is worse than none. Verified with
   a deliberately-broken standalone test (`std.testing.expect(1 == 2)`,
   never added to any module) — it fails inside the VM and `run.sh` exits
   non-zero.

## Wall time

Two different costs, not to be confused:

- **One-off provisioning** (`scripts/vm/provision.sh`, only pays when the
  recipe hash changes):
  - OpenWRT ImageBuilder: **1m48s** with the ImageBuilder tree already
    unpacked, **1m58s** cold (unpacking the 41 MB tarball first). Package
    downloads from downloads.openwrt.org are included in both.
  - Debian boot+apt: **1m12s** end to end — copy the 388 MB stock qcow2,
    boot without `-snapshot`, `apt-get update` (28.4 MB of index over slirp,
    ~38s), install, `sync`, poweroff. Measured again after adding python3 +
    pip + `pymodbus==3.14.0`: **1m45s**, and the resulting image is **752 MB**
    (was 639 MB). Measured again after adding the other four SCADA masters
    (pycomm3, bacpypes3, python-snap7, asyncua — asyncua drags in cryptography
    and pyOpenSSL, which is most of the difference): **2m39s**, image **833 MB**.
    Old provisioned images are not deleted automatically —
    `provision.sh` lists them as safe to delete, and each is ~700-850 MB.
  - Cache hit (recipe unchanged): **50 ms**, no boot, no build.
- **Steady-state `scripts/vm/run.sh`** (cache hit, no rebuild): ~20-30s per
  invocation end to end (compile + boot + transfer + run + shutdown),
  measured across a dozen+ runs of both images, provisioned and stock alike
  — provisioning only changes *which* image file gets booted, not how the
  boot/transfer/run steps work. Boot itself is ~10s of that; the rest is the
  cross-compile (dominated by `tc`'s golden-byte test tables) and the
  guest-side run. Concretely, both on provisioned images:
  `scripts/vm/run.sh tc openwrt` **26.8s** (25s of it inside the VM),
  `scripts/vm/run.sh tc debian` **20.9s** (19s inside).

## A real bug this lane found

Running `tc`'s `RTM_NEWACTION` test for the first time ever (root-only, so
it always SKIPPED on a bare host, cleanly, with `zig build test-tc` exiting
0) surfaces a **genuine, reproducible library bug**: after `sock.actionAdd`
for `gact` index 77 succeeds, `sock.actions("gact")` doesn't return an entry
whose index matches — `try testing.expect(seen)` at `modules/tc/src/
root.zig:1222` fails, deterministically, both in the full suite and isolated
with `--test-filter`.

This is not an environment or harness artifact: the real `tc` CLI round-trips
the identical `tc actions add action gact drop index 77` / `tc actions ls
action gact` sequence perfectly (`total acts 1`, index 77 present) on the
same kernel, same boot — on the Debian image, and (since provisioning) on
the OpenWRT image too, with iproute2 6.18.0 against the 6.12.87 musl kernel.
The kernel path is fine on both; something in this module's own
request-encoding or dump-decoding for the standalone action table isn't.

**Reproduces byte-identically on the provisioned OpenWRT kernel.** With
provisioning in place, `scripts/vm/run.sh tc openwrt` runs this test for
real too (previously it never even reached this code path — the kmod was
missing) and fails at the exact same `root.zig:1222` with the exact same
`TestUnexpectedResult`, same test count either side (129 passed / 1
failed) on both platforms. Same failure on two different kernels
(OpenWRT's musl/6.12.87 vs Debian's glibc/6.12.96), two different libc's,
built from the same source by two different cross-compiles, is strong
evidence the defect is in the module's own netlink encode/decode, not an
environment quirk of either guest. Left unfixed per this task's constraints
(no module-source edits) — flagged here as exactly the kind of finding a
real-root lane is supposed to produce: a test that would otherwise pass
vacuously forever (SKIP, exit 0) now fails loudly instead, identically,
everywhere it can run at all.

## Image details

| | OpenWRT | Debian |
|---|---|---|
| Version | 25.12.4, x86-64 | 13 (trixie), 20260722-2547 |
| libc | musl | glibc |
| Format | raw `.img` (ext4-combined) | qcow2 |
| Fetched from | downloads.openwrt.org | cloud.debian.org (nocloud variant) |
| Checksum | SHA-256 (of both the `.gz` and the decompressed image) | SHA-512 (Debian only publishes that) |
| Login | auto (serial askfirst console, no password) | `root` / `zigvm` (fixed, throwaway — ephemeral `-snapshot` guest, no host port exposed) |
| Provisioning input | `openwrt-imagebuilder-25.12.4-x86-64.Linux-x86_64.tar.zst` (41 MB, SHA-256 pinned) | the stock qcow2 itself, copied |
| Provisioned as | `openwrt-25.12.4-x86-64-ext4-prov-<recipe12>.img` (raw, 121 MB) | `debian-13-nocloud-amd64-prov-<recipe12>.qcow2` (639 MB after apt) |
| Provisioned login | unchanged (auto) | unchanged; `systemd-firstboot` has now genuinely completed *on disk*, so later boots skip the wizard rather than answering it from fw_cfg every time |

Both pinned in `scripts/vm/manifest.sh` with exact URLs and checksums,
verified after every download — a mismatch deletes the partial file and
aborts loudly rather than booting something unverified. `scripts/vm/
fetch-images.sh` prefers an existing local copy of the OpenWRT image
(`~/workspace/axp/DEV/vm-openwrt/`) over re-downloading 126 MB this dev
machine already has, but the download path is exercised and works from a
fresh clone too (this is only a fast-path, not the only path).

Neither image is ever committed — see the repo's `.gitignore`
(`scripts/vm/images/`, `scripts/vm/work/`). That covers the provisioned
images too: they are build artifacts, reproducible on a fresh clone with
`scripts/vm/fetch-images.sh && scripts/vm/provision.sh`. The stock images are
never written to by provisioning (OpenWRT's is not even an input — the
ImageBuilder is; Debian's is copied first), so their pinned checksums keep
verifying forever.
