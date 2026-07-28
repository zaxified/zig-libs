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
scripts/vm/fetch-images.sh          # one-time, ~530 MB total
scripts/test.sh vm tc               # or: scripts/vm/run.sh tc debian
```

## What actually works — verified, not assumed

The brief handed to build this assumed OpenWRT would cover the tc gap and
that Debian's "nocloud" cloud image needed no seeding. Both assumptions were
wrong; here's what's actually true, checked by booting real VMs and running
real test binaries in them (not by reading docs):

- **OpenWRT's default x86-64 build has no `tc` support at all.** No `tc`
  binary, and none of `sch_netem`/`sch_htb`/`sch_tbf`/`act_gact`/`cls_u32`/
  `cls_flower` load (`modprobe` reports "not found" for every one) — this is
  a genuine kernel-config gap, not a privilege wall. `tc` tests are routed
  to Debian, whose generic cloud kernel (6.12.96) loads all of those
  cleanly and ships `tc`/iproute2 6.15.
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
| `tc` | debian | execution-verified (kernel modules load; `tc` CLI round-trips) |
| `nftables` | openwrt | execution-verified (73 tests incl. live round-trip) |
| `conntrack` | openwrt | execution-verified (28 tests) |
| everything else | debian (default) | most NETNS_MODULES don't need this lane at all — `unshare -rn` already covers them (see `scripts/test.sh`'s own `NETNS_MODULES` comment); route here only for isolation, not privilege |

Override with `scripts/vm/run.sh <module> openwrt|debian` when the default
routing is wrong for your case. The table lives in `scripts/vm/run.sh`
(`route_platform`), not duplicated here, so there's one place to update.

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

~20-30s per `scripts/vm/run.sh` invocation end to end (compile + boot +
transfer + run + shutdown), measured across a dozen+ runs of both images.
Boot itself is ~10s of that; the rest is the cross-compile (dominated by
`tc`'s golden-byte test tables) and the guest-side run.

## A real bug this lane found

Running `tc`'s `RTM_NEWACTION` test for the first time ever (root-only, so
it always SKIPPED on a bare host, cleanly, with `zig build test-tc` exiting
0) surfaces a **genuine, reproducible library bug**: after `sock.actionAdd`
for `gact` index 77 succeeds, `sock.actions("gact")` doesn't return an entry
whose index matches — `try testing.expect(seen)` at `modules/tc/src/
root.zig:1222` fails, deterministically, both in the full suite and isolated
with `--test-filter`.

This is not an environment or harness artifact: the real `tc` CLI (present
on the Debian image) round-trips the identical `tc actions add action gact
drop index 77` / `tc actions ls action gact` sequence perfectly (`total acts
1`, index 77 present) on the same kernel, same boot. The kernel path is
fine; something in this module's own request-encoding or dump-decoding for
the standalone action table isn't. Left unfixed per this task's constraints
(no module-source edits) — flagged here as exactly the kind of finding a
real-root lane is supposed to produce: a test that would otherwise pass
vacuously forever (SKIP, exit 0) now fails loudly instead.

## Image details

| | OpenWRT | Debian |
|---|---|---|
| Version | 25.12.4, x86-64 | 13 (trixie), 20260722-2547 |
| libc | musl | glibc |
| Format | raw `.img` (ext4-combined) | qcow2 |
| Fetched from | downloads.openwrt.org | cloud.debian.org (nocloud variant) |
| Checksum | SHA-256 (of both the `.gz` and the decompressed image) | SHA-512 (Debian only publishes that) |
| Login | auto (serial askfirst console, no password) | `root` / `zigvm` (fixed, throwaway — ephemeral `-snapshot` guest, no host port exposed) |

Both pinned in `scripts/vm/manifest.sh` with exact URLs and checksums,
verified after every download — a mismatch deletes the partial file and
aborts loudly rather than booting something unverified. `scripts/vm/
fetch-images.sh` prefers an existing local copy of the OpenWRT image
(`~/workspace/axp/DEV/vm-openwrt/`) over re-downloading 126 MB this dev
machine already has, but the download path is exercised and works from a
fresh clone too (this is only a fast-path, not the only path).

Neither image is ever committed — see the repo's `.gitignore`
(`scripts/vm/images/`, `scripts/vm/work/`).
