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

## Testing

The real enforcement tests **fork a child**, apply the restriction, attempt the
now-forbidden action, and assert the child dies / EPERMs as configured while a
control child without the restriction succeeds — the only honest way to verify
a security boundary.

```
zig build test-sandbox                          # 10 pass, 2 skip (priv-drop is root-gated)
zig build test-sandbox -Doptimize=ReleaseFast
```

- **seccomp** — a child installs a filter that omits `getpid`; with
  `.kill_process` the child dies of `SIGSYS`, with `.{ .errno = EPERM }` the
  call returns `-EPERM`; the control child (getpid allowed) runs fine.
- **Landlock** — a child restricted to a temp dir cannot open `/etc/passwd`
  but can still read the allowed file. Skips on a pre-5.13 kernel.
- **rlimit** — a child caps `RLIMIT_NOFILE`, exhausts it (EMFILE at the cap),
  and confirms it cannot raise the hard limit back.
- **privilege drop** — needs to *start* as root; drops to `nobody` and asserts
  it cannot `setuid(0)` back. Skips cleanly when not run as root:

```
sudo zig build test-sandbox                     # 12 pass (adds the priv-drop tests)
```

## Deferred (v2)

- seccomp **argument** filtering (match on `seccomp_data.arg*`, not just `nr`) —
  e.g. allow `socket(AF_INET)` but deny `AF_PACKET`.
- The `seccomp(2)` syscall form with `TSYNC` to apply a filter across all
  threads of an already-multi-threaded process (the prctl form here filters the
  calling thread; install before spawning workers).
- Landlock **network** rules (`LANDLOCK_RULE_NET_PORT`, ABI 4+) and the
  scoped-abstraction rules (ABI 6+).
- Remains Linux-only — the documented ceiling (no OpenBSD `pledge`/`unveil`,
  no FreeBSD Capsicum).
