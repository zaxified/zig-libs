# sandbox

Linux **process self-hardening** for an internet-facing server, in pure Zig — a
set of composable, opt-in steps a daemon calls at startup (after it has bound
its sockets and opened every privileged resource) to shave the kernel's attack
surface down to what a request loop actually touches. No libseccomp, no libcap,
no libc.

Five independent steps, weakest-precondition first:

1. **no-new-privs** — `prctl(PR_SET_NO_NEW_PRIVS)`. Neutralises setuid bits /
   file caps on any future execve, and is the precondition for an unprivileged
   seccomp filter.
2. **privilege drop** — `setgroups([]) → setgid → setuid`, in that exact order
   (setuid *before* setgid is the classic hole), then a **read-back** that the
   drop stuck. Optional capability bounding-set drop (`PR_CAPBSET_DROP`) and a
   `capset`-based clear of the held sets.
3. **rlimits** — `setrlimit` helpers, including `disableCoreDumps`
   (`RLIMIT_CORE=0`) so a crash can't spill in-memory keys to a core file.
4. **Landlock** — an unprivileged filesystem **allow-list** (kernel ≥ 5.13):
   handle a set of access rights, allow-list specific paths, `restrict_self`.
   ABI version is negotiated; a too-old kernel returns a typed error.
5. **seccomp-bpf** — a classic-BPF syscall **allow-list** installed via
   `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`, with a configurable action for
   denied calls (kill the process, or return an errno). Ships a tunable default
   allow-list for a non-blocking network server.

- **Model after:** the Linux kernel UAPI (`prctl`/`seccomp`/`landlock`/
  `capability`) plus the sandboxing shape of OpenSSH's seccomp filter and
  systemd's `NoNewPrivileges` / `SystemCallFilter` / uid-drop.
- **Why:** the collection had no OS-hardening primitive — nothing did
  seccomp / Landlock / priv-drop, the biggest structural gap for a server that
  faces the internet. std has none of these.
- **Platform:** linux (raw `std.os.linux` syscalls, no libc — a conscious
  ceiling, like `netlink` / `rawsock`). **Role:** util. **Concurrency:**
  single_owner (applied once, at startup, by the owning thread).
- **Deps:** none.
- **Privileges:** seccomp, Landlock and lowering an rlimit are all
  **unprivileged**. Privilege drop and capability-set changes require starting
  privileged; the calls surface a typed `error.SetIdFailed` /
  `error.PermissionDenied` otherwise.

Provenance: original work of the zig-libs authors (MIT). All ABI constants,
struct layouts and the seccomp BPF program are clean-room from the kernel UAPI
(`prctl.h`, `seccomp.h`, `landlock.h`, `capability.h`, `audit.h`); no
third-party implementation was ported or studied. See SPEC.md for the citation.

## API

```zig
const sandbox = @import("sandbox");

// Do this LAST, after bind()/listen() and opening every privileged fd.

// 1. no-new-privs (also required before an unprivileged seccomp filter).
try sandbox.noNewPrivs();

// 2. rlimits.
try sandbox.disableCoreDumps();          // RLIMIT_CORE = 0
try sandbox.limitOpenFiles(1024);        // RLIMIT_NOFILE
try sandbox.limitProcesses(64);          // RLIMIT_NPROC

// 3. drop root → an unprivileged service account (order-safe + verified).
try sandbox.dropPrivileges(.{ .uid = 65534, .gid = 65534 });
sandbox.dropCapabilityBoundingSet() catch {}; // best-effort; needs CAP_SETPCAP

// 4. Landlock filesystem allow-list (kernel >= 5.13).
if (sandbox.landlockAbiVersion()) |_| {
    var ll = try sandbox.Landlock.init(sandbox.Landlock.access.read_only);
    defer ll.deinit();
    try ll.allowPath("/var/www", sandbox.Landlock.access.read_only);
    try ll.allowPath("/var/lib/app", sandbox.Landlock.access.read_write);
    try ll.restrictSelf(); // needs noNewPrivs() first
} else |_| { /* kernel too old / disabled — log and continue */ }

// 5. seccomp syscall allow-list — kill the process on anything off the list.
const prog = try sandbox.seccomp.buildDefault(gpa, .kill_process);
defer gpa.free(prog);
try sandbox.seccomp.install(prog);       // needs noNewPrivs() first

// Or hand-roll an allow-list and pick a soft failure mode:
const custom = [_]std.os.linux.SYS{ .read, .write, .close, .exit_group };
const p2 = try sandbox.seccomp.build(gpa, &custom, .{ .errno = 1 }); // EPERM
defer gpa.free(p2);

// W^X preset: layer an argument check onto mmap/mprotect/pkey_mprotect that
// denies PROT_WRITE|PROT_EXEC together, independent of the plain allow-list.
const wx = try sandbox.seccomp.buildDefaultWx(gpa, .kill_process, .{ .errno = 1 });
defer gpa.free(wx);
try sandbox.seccomp.install(wx);

// Already multi-threaded at hardening time? install() only filters the
// calling thread — use the seccomp(2)+TSYNC form to cover every thread.
try sandbox.seccomp.installTsync(prog);
```

### Landlock access rights

`Landlock.access` mirrors `LANDLOCK_ACCESS_FS_*` (`execute`, `read_file`,
`write_file`, `read_dir`, `make_reg`, `truncate`, …) plus two convenience
unions: `read_only` (read a file + list a dir) and `read_write` (read/write/
create/remove regular files). A ruleset's handled mask is intersected with what
the running ABI supports, so the same code degrades cleanly across kernels.

### seccomp default allow-list

`seccomp.default_allowlist` is a curated set for a generic non-blocking network
server's hot loop (read/write/recvfrom/sendto/epoll/accept/close/futex/mmap/
timers/getrandom/…), resolved to the target arch at comptime. It is a
**starting point** — profile your binary (`strace -f -c`) and trim or extend it.
Too tight bricks the process; too loose defeats the sandbox. The filter always
guards `seccomp_data.arch` first so a foreign ABI (e.g. x86-64's x32) can't slip
past a number-only allow-list.

### seccomp W^X preset

`seccomp.buildWx` / `buildDefaultWx` layer an argument check onto `mmap`,
`mprotect` and `pkey_mprotect` (when present in the arch's `linux.SYS`): if a
call requests `PROT_WRITE` **and** `PROT_EXEC` together, it is denied via a
separate `wx_action`, independent of the plain `on_deny` used for syscalls
that aren't allow-listed at all — the same way an arch mismatch is always
`KILL_PROCESS` regardless of the caller's chosen deny action. The check is a
bitmask test (`prot & (WRITE|EXEC) == (WRITE|EXEC)`), not an equality, so
`READ|WRITE|EXEC` doesn't slip past it, and both 32-bit halves of the 64-bit
argument register are inspected (a non-zero high half is a violation too) —
a filter that only ever looks at the low half is checking a different value
than the kernel will actually see if a raw syscall (bypassing libc's normal
int-argument zero-extension) puts something in the upper 32 bits.

### seccomp(2) + TSYNC

`seccomp.installTsync` installs a program via the `seccomp(2)` syscall with
`SECCOMP_FILTER_FLAG_TSYNC` instead of `prctl(PR_SET_SECCOMP)`, applying it to
every thread of the calling process in one atomic step — `install()`'s prctl
form only ever filters the calling thread, so a worker spawned before
hardening runs stays unfiltered. `TSYNC`'s failure mode is unusual: on a
thread-sync failure the raw return value is the tid of the first thread that
couldn't sync, not a negated errno, so `installTsync` distinguishes
`error.ThreadSyncFailed` from a plain `error.SeccompFailed`.

## Testing

The real enforcement tests **fork a child**, apply the restriction, attempt the
now-forbidden action, and assert the child dies / EPERMs as configured while a
control child without the restriction succeeds — the only honest way to verify
a security boundary.

```
zig build test-sandbox                          # priv-drop tests are root-gated (skip otherwise)
zig build test-sandbox -Doptimize=ReleaseFast
```

- **seccomp** — a child installs a filter that omits `getpid`; with
  `.kill_process` the child dies of `SIGSYS`, with `.{ .errno = EPERM }` the
  call returns `-EPERM`; the control child (getpid allowed) runs fine. The
  same KILL/ERRNO shape is re-verified through `installTsync` (the
  `seccomp(2)` path, not `prctl`), plus a dedicated test that spawns a worker
  thread *before* installing the filter and confirms the `TSYNC` sync reaches
  it too (the worker's own denied syscall brings down the whole process,
  which `install()`'s prctl form could never do).
- **seccomp W^X** — a child installs `buildWx`; `mprotect(RW)` and
  `mmap(RW)` still succeed, `mprotect(RWX)` / `mmap(RWX)` are denied, and a
  raw syscall with a crafted non-zero high word on an otherwise-safe `prot`
  value is denied too (proving the 64-bit argument check, not just the low
  word, is active).
- **Landlock** — a child restricted to a temp dir cannot open `/etc/passwd`
  but can still read the allowed file. Skips on a pre-5.13 kernel.
- **rlimit** — a child caps `RLIMIT_NOFILE`, exhausts it (EMFILE at the cap),
  and confirms it cannot raise the hard limit back.
- **privilege drop** — needs to *start* as root; drops to `nobody` and asserts
  it cannot `setuid(0)` back. Skips cleanly when not run as root:

```
sudo zig build test-sandbox                     # adds the priv-drop tests
```

## Deferred (v2)

- seccomp **argument** filtering beyond the W^X preset — e.g. allow
  `socket(AF_INET)` but deny `AF_PACKET`, or gate `ioctl` requests. The W^X
  preset (`buildWx`/`buildDefaultWx`) and `seccomp(2)`+`TSYNC`
  (`installTsync`) are both built; general-purpose arg matching on arbitrary
  syscalls/argument indices is not.
- Landlock **network** rules (`LANDLOCK_RULE_NET_PORT`, ABI 4+) and the
  scoped-abstraction rules (ABI 6+).
- Remains Linux-only — the documented ceiling (no OpenBSD `pledge`/`unveil`,
  no FreeBSD Capsicum).
