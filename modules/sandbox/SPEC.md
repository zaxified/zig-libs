# sandbox — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT) — see the UAPI citation below.

## UAPI citation (why no NOTICE entry)

Every constant, struct layout and the seccomp BPF program are **clean-room from the Linux kernel
UAPI** — an OS ABI, not a copyrightable work (merger doctrine: there is exactly one way to spell
`PR_SET_NO_NEW_PRIVS = 38` or `struct sock_filter`). No third-party implementation
(libseccomp, libcap, systemd, OpenSSH's `sandbox-seccomp-filter.c`, Cloudflare's sandbox) was
ported or studied for algorithm/API shape; those are named only as prior art that hardens the same
way. Per CONVENTIONS.md §5 a pure clean-room-from-UAPI module needs **no NOTICE entry** — the
citation lives here:

- `prctl.h` — `PR_SET_NO_NEW_PRIVS` (38), `PR_SET_SECCOMP` (22), `PR_CAPBSET_DROP` (24).
- `seccomp.h` — `SECCOMP_MODE_FILTER` (2), `SECCOMP_RET_*` action words, `struct seccomp_data`.
- `filter.h` / `bpf_common.h` — classic-BPF `struct sock_filter` (8 bytes) + `sock_fprog`, opcode
  classes (BPF_LD/JMP/RET, BPF_W/ABS, BPF_JEQ/K).
- `landlock.h` — `landlock_create_ruleset`/`add_rule`/`restrict_self` (syscalls 444/445/446),
  `struct landlock_ruleset_attr`, packed `struct landlock_path_beneath_attr`, `LANDLOCK_ACCESS_FS_*`,
  the ABI-version negotiation via `LANDLOCK_CREATE_RULESET_VERSION`.
- `capability.h` — `_LINUX_CAPABILITY_VERSION_3` (0x20080522), the v3 two-word data layout.
- `audit.h` + `elf.h` — `AUDIT_ARCH_*` = `EM_<arch>` OR'd with the 64-bit/little-endian flags,
  computed directly (std's `linux.AUDIT.ARCH` enum is unbuildable in Zig 0.16 — a bad `elf.EM.FRV`
  member — so the arch token is derived clean-room from `builtin.cpu.arch`).

## Design & invariants

- **Five independent, opt-in steps; the caller picks and orders them.** A server applies these last,
  after `bind`/`listen` and opening every privileged fd. Nothing here is a global — each function is
  a thin, verified wrapper over one syscall family.
- **Order-safety is enforced, not documented.** `dropPrivileges` does `setgroups([]) → setgid →
  setuid` (the only safe order — setuid first strips the privilege setgid/setgroups themselves need)
  and then **reads back** real, effective AND saved uid/gid (`getresuid`/`getresgid` — the saved id
  is the `seteuid` ladder back up) plus `getgroups() == 0`, returning `error.DropNotEffective` on
  any mismatch. A partial/spoofed drop is fatal, never silently tolerated. The capability bounding
  set must be dropped BEFORE `dropPrivileges`: `PR_CAPBSET_DROP` needs `CAP_SETPCAP`, which a
  non-root uid no longer holds (the earlier README recipe had it after, where it always hit EPERM and
  a `catch {}` swallowed it).
- **seccomp is an allow-list with a mandatory arch guard.** The generated classic-BPF program loads
  `seccomp_data.arch`, KILLs on a mismatch (always KILL, independent of the configured deny action),
  loads `nr`, then a linear `JEQ nr_i → ALLOW` chain with a single deny leaf. What the guard is FOR:
  a syscall entered through a foreign ABI's entry point, where the same number is a different call —
  on x86-64 the i386 `int $0x80` entry reports `AUDIT_ARCH_I386` and its nr 39 is `mkdir`, while the
  allow-listed x86-64 nr 39 is `getpid`; measured, a getpid-only filter without the guard created a
  directory. What it is NOT for: x32. The x32 ABI reports `AUDIT_ARCH_X86_64` (measured) and passes
  the guard; it is stopped by default-deny, because an x32 number carries `__X32_SYSCALL_BIT`
  (`0x40000000`) and never equals a bare allow-listed `nr`. Both `build` and `buildWx` are pinned
  structurally (opcode, `k`, AND the jump targets `jt`/`jf` — a `jf: 0 → 1` mutation keeps opcode and
  `k` and makes the KILL leaf unreachable) and behaviourally on x86-64 (a child issues `int $0x80`
  nr 39 and must die of SIGSYS). Jump offsets (`jt`) are a `u8`, so the flat encoding caps at 255
  allowed calls (`error.TooManySyscalls` past that). `Action.errno` must be in `1..4095`
  (`error.InvalidErrno`): `0` would make a denied syscall report SUCCESS, and the kernel clamps
  above 4095. The default allow-list is comptime-filtered by `@hasField(linux.SYS, name)` so it stays
  valid on any arch — and a test names its content (and, on x86-64, that exactly one spelling is
  dropped), because that filter also swallows a misspelling silently: syscall 262 is `newfstatat` in
  some tables and `fstatat64` in std's x86-64 table, and only the former was listed, so C code's
  `stat(2)` died of SIGSYS under a list whose author had allowed it. Audit S11 (2026-09-14): 12
  calls a runtime makes unasked were added (`rseq`, `set_robust_list`, `getdents64`, `epoll_pwait2`,
  `clock_getres`, `sched_getaffinity`, `getrusage`, `uname`, `sysinfo`, `close_range`, `faccessat2`,
  `rt_sigtimedwait`), each checked to touch only the caller's own state, an fd it holds, or
  information `newfstatat`/`statx` already expose; a test runs all 12 under the installed default
  filter. `prlimit64` and `setrlimit` were listed by the audit and stay OUT: both raise soft limits
  the `limit*` helpers lowered, and `prlimit64` acts on other same-uid processes — a new grant (the
  same test pins that the default filter kills them). `sock_filter` is asserted 8 bytes; `landlock_path_beneath_attr` asserted 12
  (packed u64+s32) so the byte layout matches the kernel's `copy_from_user`.
- **The W^X preset (`seccomp.buildWx`/`buildDefaultWx`) adds argument-checked blocks, not a
  different filter shape.** For each of `{mmap, mprotect, pkey_mprotect}` present in the allow-list,
  a self-contained 9-instruction block sits ahead of the plain nr dispatch: reload `nr`, compare to
  this syscall (local jump, skip the block on mismatch), load the high 32 bits of `arg2` (`prot`) and
  deny if non-zero, load the low 32 bits, `AND` with `PROT_WRITE|PROT_EXEC`, and deny if the result
  equals the mask (both bits set) — otherwise `ALLOW` directly. Every jump inside a block is a small
  local offset (0/1/3/7), so blocks don't need to know the program's total length or each other's
  position, unlike the plain dispatch chain (which needs the overall count for its descending `jt`).
  Two things a naive version gets wrong: comparing `prot == (WRITE|EXEC)` instead of a masked AND
  (misses `READ|WRITE|EXEC`), and inspecting only the low 32-bit half of the 64-bit `arg2` register
  (a raw syscall bypassing libc's int zero-extension can put anything in the high half, so a
  low-word-only filter is checking a different value than what actually reaches the kernel — a
  non-zero high word is treated as a violation here, not ignored). `PROT_WRITE`/`PROT_EXEC` are
  hardcoded (`0x2`/`0x4`, `mman-common.h`, identical on every Linux arch) rather than taken from
  std's `linux.PROT`, whose packed-struct field layout isn't a byte-order-independent value to
  compare inside a BPF program. **What the preset guarantees, precisely:** no single `mmap`/
  `mprotect`/`pkey_mprotect` call may request `PROT_WRITE` and `PROT_EXEC` together. It does NOT
  prevent the two-step `mmap(RW)` → write code → `mprotect(RX)` → execute sequence (measured: a
  function written that way returned), because `RX` alone never trips the mask. That is the shape
  every JIT and `dlopen` use, and refusing it (deny `PROT_EXEC` on `mprotect` entirely) would break
  them — so this preset is "no simultaneous W|X", not W^X in the strict sense. A caller who needs the
  strict property adds a rule denying `PROT_EXEC` on `mprotect` for its own binary.
- **`seccomp.installTsync` uses the `seccomp(2)` syscall (not `prctl`) with `SECCOMP_FILTER_FLAG_TSYNC`**
  to apply a filter to every thread of the process atomically, for the case where hardening happens
  after workers already exist (`install()`'s prctl form only ever touches the calling thread).
  `TSYNC`'s failure convention is the trap: on a thread-sync failure the raw return value is the
  *positive tid* of the first thread that failed to sync — not a negated errno — so reusing
  `install()`'s `linux.errno(rc) != .SUCCESS` check here would silently read that as success (a
  positive value decodes to `.SUCCESS` under `linux.errno`'s `(-4096, 0)` window). `installTsync`
  checks for this explicitly and reports `error.ThreadSyncFailed` rather than `error.SeccompFailed`.
- **Landlock: `init()` handles everything; `allowPath` grants.** Landlock only restricts rights
  that are *handled*; an unhandled right is unrestricted everywhere. `Ruleset.init()` therefore
  handles `access.all` (every `LANDLOCK_ACCESS_FS_*` bit this module knows, clamped to the ABI) and
  `allowPath(path, rights)` says what each tree may be used for. The earlier `init(handled)` took a
  mask, and every piece of documentation passed `access.read_only` to BOTH calls — a ruleset that
  handled `read_file|read_dir` only, leaving the other 14 rights (write, create, unlink, mkdir,
  symlink, truncate, …) unrestricted for the whole filesystem. The A1 audit measured a process
  "confined to a read-only tree" creating, truncating, unlinking and symlinking outside it, and
  writing inside it. The explicit form survives as `initHandling(mask)` for the rare deployment that
  wants a right left unhandled on purpose. `allowPath` opens with `O_NOFOLLOW` and refuses a final-
  component symlink (`error.PathIsSymlink`) — a rule attaches to what the configuration names, not to
  what a symlink (writable by anyone with write access to its parent) points at; one
  `link_to_root -> /` had granted the whole filesystem. Intermediate symlink components are still
  followed.
- **Landlock degrades, never faults, on old kernels.** The ABI version is queried first
  (`landlock_create_ruleset(NULL,0,VERSION)`); the handled-access mask and each rule's allowed-access
  are intersected with the bits that ABI understands, so passing a newer access bit to an older
  kernel can't trigger EINVAL. Pre-5.13 / disabled surfaces as `error.NotSupported` / `error.Disabled`.
- **Raw errno syscalls, no libc.** Every call goes through `std.os.linux` directly (`prctl`,
  `setgroups`/`setgid`/`setuid`, `setrlimit`, `capset`, and `syscall2/3/4` for the three landlock
  numbers). Failures are typed errors; there is no path that panics on a malformed or
  unsupported-kernel result — a server must be able to log and choose policy.
- **Concurrency:** single_owner — applied once at startup by the owning thread. The prctl-form
  seccomp install and Landlock `restrict_self` affect the CALLING THREAD (and its future children).
  For seccomp, `installTsync` reaches threads that already exist. **For Landlock there is no
  equivalent** — the kernel offers no TSYNC flag for `landlock_restrict_self` — so a worker spawned
  before `restrictSelf` stays unconfined for good (measured: main thread EACCES, pre-existing worker
  SUCCESS on the same path; pinned by a test). Restrict before spawning workers.

## Threat model / out of scope

**Linux-only by design** — no OpenBSD `pledge`/`unveil`, no FreeBSD Capsicum, no cross-platform
abstraction attempted. This module **reduces** a process's own privilege; it is not an access-control
policy engine and does not decide *what* a service may do — that is the deployment's choice, encoded
in the allow-lists/paths/ids the caller passes. **Irreversibility is the point:** no-new-privs,
seccomp, Landlock `restrict_self` and a real uid drop cannot be undone, so a bug that hardens too
aggressively bricks the process (fail-closed) rather than silently leaving it open — the audit
concern is a filter that is too *loose* (defeats the purpose) far more than one too tight. The
default seccomp allow-list is explicitly a **starting point** to be profiled and tuned per binary,
not a vetted policy for any given program; shipping it unmodified can either break a program that
uses a syscall it omits or leave reachable a syscall it includes. The plain `build`/`install` path
filters on the syscall *number* only — argument filtering beyond the W^X preset (e.g. restricting
`socket` address families or `ioctl` requests) is deferred, so a number-level allow of
`ioctl`/`socket` still admits every variant; `mmap`/`mprotect`/`pkey_mprotect` get the one argument
check this module ships (`buildWx`/`buildDefaultWx`, PROT_WRITE|PROT_EXEC). Landlock covers the
filesystem (and, when built out, network ports); it does not restrict already-open fds, IPC, or
ptrace — pair it with seccomp + a namespace for those. Out of scope: general seccomp arg matching
(non-PROT), Landlock net/scoped rules, BSD sandboxing.

## Verification

The enforcement tests **fork a child**, apply one restriction, attempt the forbidden action and
assert the child terminates exactly as configured, with a control child (no restriction) succeeding —
the only honest way to test a security boundary; a pure unit test would prove nothing about the
kernel actually enforcing it. **Skips are decided before the child runs**, from a probe of the
kernel (`seccomp.available()`, `landlockAbiVersion()`, a writable `/tmp`, `int $0x80` being
emulated) — never from the child's own failure exit. The earlier shape `if (child failed to
install) return error.SkipZigTest` turned a broken mechanism into a green suite (A1 audit S5: a
mutation disabling Landlock entirely produced "15 pass / 3 skip", exit 0); now `init`/`install`
failing after the probe said yes is a failing test. `runInChild` checks `waitpid`'s return too — a
failed wait used to leave `status = 0`, which reads as "exited 0". Unprivileged and always-run: seccomp (KILL child dies of `SIGSYS`,
ERRNO child sees `-EPERM`, control survives), the same KILL/ERRNO shape re-verified through
`installTsync`'s `seccomp(2)` path, a cross-thread test that spawns a worker *before* installing
(via `installTsync`) and confirms the worker's own denied syscall brings the whole process down
(proof `TSYNC` actually reached a thread that never called into seccomp itself — `install()`'s
prctl form cannot do this), the W^X preset (RW `mprotect`/`mmap` still succeed; RWX denied; a raw
syscall with a crafted non-zero high word on the `prot` argument is denied too, proving the 64-bit
argument check and not just its low half is active), the arch guard's real job on x86-64 (a child
under a getpid-only filter — `build` and `buildWx` — issues `int $0x80` nr 39, the i386 `mkdir`, and
must die of SIGSYS; a directory appearing is the escape), Landlock (child confined to a temp dir is
denied `/etc/passwd`, allowed its own file; with `init()` + `allowPath(read_only)` it is denied
create/overwrite/mkdir/symlink/unlink outside the tree and writes inside it, while `read_write` on
the tree still permits creating there; a symlink handed to `allowPath` is refused by name; a worker
spawned before `restrictSelf` is measured unconfined — skips pre-5.13), rlimit (`RLIMIT_NOFILE`
bites at the cap with EMFILE and cannot be raised back; `RLIMIT_CORE` read back as 0). Root-gated +
`SkipZigTest` otherwise: privilege drop (drops to `nobody`, asserts uid AND gid AND saved uid, and
that `setuid(0)`/`setgid(0)` fail) and capability bounding-set drop — ⚠ in an unprivileged run
these two are inert, so the setuid-before-setgid hole is NOT caught by the ordinary gate; a
privileged lane is the only cure, and it exists: `scripts/vm/run.sh sandbox` runs the suite as real
root in a disposable guest (2026-09-15: 35 pass, and seven drop/bounding-set mutants each fail
there). The typed failure branches no healthy kernel takes (`install`/`installTsync` errno,
Landlock ENOSYS/EOPNOTSUPP) are driven by a seccomp pre-filter that makes the real syscall return
that errno, in every ordinary run. `run.sh sandbox debian --kernel-append lsm=apparmor` also checks
`error.Disabled` against a kernel without the Landlock LSM. Pure/logic tests cover the BPF program shape for `build` AND
`buildWx` (arch guard including its jump targets, per-syscall compare, W^X block layout, allow/deny
leaves, descending `jt`), the default allow-list's named content, `Action.errno` bounds, struct ABI
sizes, and the monotone Landlock access mask. Run:
`zig build test-sandbox` (add `-Doptimize=ReleaseFast` for the release check; `sudo` prefix to also
exercise the two root-gated tests).

## Backlog / deferred

- **General seccomp argument filtering** — match on `seccomp_data.arg*` for arbitrary
  syscalls/argument indices (e.g. gate `socket` families, `ioctl` requests). The one instance built
  so far is the W^X preset (`buildWx`/`buildDefaultWx`, PROT_WRITE|PROT_EXEC on
  mmap/mprotect/pkey_mprotect) — a general-purpose arg-rule builder for other syscalls is not.
- **Landlock network + scoped rules** — `LANDLOCK_RULE_NET_PORT` (ABI 4), scoped-abstraction (ABI 6).
- **Remains Linux-only** — the documented ceiling (no `pledge`/Capsicum) is permanent, not a gap.

## Status

`new · linux · util · single_owner` + deps: none — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** seccomp/landlock/rlimit enforcement tested against the real running kernel
