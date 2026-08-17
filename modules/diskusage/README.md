# diskusage

Filesystem space + mount table, without spawning `df`/`mount`: a raw
`statfs(2)`/`statfs64(2)` syscall wrapper (total/free/available bytes, inode
counts, block size, filesystem type) plus parsers for `/proc/self/mounts`
(the simple `mtab`(5)-shaped four-column table) and `/proc/self/mountinfo`
(the richer source — mount ID/parent ID, the mount's root within its
filesystem, `major:minor` — that `findmnt`/`libmount` actually read).

Provenance: clean-room from `statfs(2)`, `proc(5)` and the kernel UAPI
headers (`include/uapi/asm-generic/statfs.h` and the per-architecture
overrides in `arch/{x86,arm,mips}/include/uapi/asm/statfs.h`) — no
third-party source ported, so no `NOTICE` entry is required (root
[`NOTICE`](../../NOTICE) §0). One design reference was studied, not ported:
musl libc's `src/stat/statvfs.c` (MIT) for its syscall-selection strategy —
`statfs64` with an explicit `sizeof(*buf)` where the target has it,
otherwise plain `statfs` — mirrored here because a native 64-bit `statfs`
struct already has 64-bit counters and gains nothing from the wider syscall.
No musl source was copied. The `src/testdata/*_sample.txt` fixtures are raw
captures of this host's own live `/proc/self/mounts`/`mountinfo` output (no
third-party data); `src/testdata/*_escaped.txt` are hand-authored by our own
tooling to exercise the octal-escape path deterministically.

- **Model after:** musl libc (syscall selection) + `statfs(2)`/`proc(5)` (wire
  formats).
- **Platform:** linux (raw `statfs`/`statfs64` syscalls, no libc; `/proc`
  reads). **Role:** util. **Concurrency:** reentrant (no shared state).
- **Deps:** none.

## Why this exists, and why it is not part of `procnet`

`procnet` already parses `/proc` text files, and it was the obvious first
place to look. Its own `SPEC.md` backlog names this gap explicitly and
declines it: *"`statvfs`/`/proc/mounts` disk usage — filesystem space, not a
`/proc/net` or per-process concern; a different module axis entirely."*
`procnet`'s design is ARP/routes/sockets/conntrack/process — everything it
covers is either `/proc/net/*` or per-process, and its typed results
(`netaddr.Ip`/`Prefix`) exist because that's what those tables carry. Disk
usage shares none of that shape: no socket, no process, no network address —
just "how full is this filesystem, and what's mounted". Folding it into
`procnet` would mean a consumer that only wants `df`-style numbers pulling in
socket-table and conntrack-flow parsing to get them, for a coincidence of
directory (`/proc`) rather than a shared concern. A sibling module keeps the
dependency honest: `diskusage` imports nothing, and nothing that wants disk
space has to import ARP/routing/socket parsing to get it.

What would have made the other call correct: if disk usage were *itself*
`/proc/net`-shaped or process-shaped — it is not. `statfs(2)` is a syscall,
not a `/proc` read at all; the `/proc/self/mounts`/`mountinfo` half is
`/proc`-adjacent only in the sense that most things on Linux eventually are.

## API

```zig
const diskusage = @import("diskusage");

// statfs(2): total/free/available bytes, inodes, block size, fs type magic.
const u = try diskusage.query("/var/log");
// or: diskusage.statfs.query(...) — same function, submodule path.
std.log.info("{d} MB available of {d} MB", .{
    u.availableBytes() / (1024 * 1024),
    u.totalBytes() / (1024 * 1024),
});

var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();

// /proc/self/mounts — device, mount point, fs type, options.
if (try diskusage.mounts.readMounts(gpa, io)) |mnts| {
    defer diskusage.mounts.freeAll(gpa, mnts);
    for (mnts) |m| std.log.info("{s} on {s} ({s})", .{ m.device, m.mount_point, m.fs_type });
}

// /proc/self/mountinfo — mount ID/parent ID/root/major:minor, for anything
// that needs the mount tree or must tell a bind mount from a full one.
if (try diskusage.mountinfo.readMountinfo(gpa, io)) |mnts| {
    defer diskusage.mountinfo.freeAll(gpa, mnts);
    for (mnts) |m| std.log.info("id={d} parent={d} {s} -> {s}", .{ m.mount_id, m.parent_id, m.mount_source, m.mount_point });
}
```

`Usage.blocks_free` (`f_bfree`) and `Usage.blocks_available`
(`f_bavail`)/`availableBytes()` are **not the same number** — they differ by
the margin a filesystem reserves for its superuser (ext-family: `tune2fs
-m`). `df`(1) reports its "Available" column, and computes its use
percentage, from `f_bavail`; a consumer replacing `df` output should read
`availableBytes()`, not `freeBytes()`.

`mounts.parseMounts`/`mountinfo.parseMountinfo` are pure (`(gpa, text) →
[]Entry`, golden-text tested against real kernel captures in `src/testdata/`,
including octal-escaped paths — see `mounts.unescapeOctal`'s doc comment);
`readMounts`/`readMountinfo` are the thin live-file wrappers. A missing or
unreadable `/proc` file returns `null`, not an error.

## DEFER (beyond this module's current scope)

- Filesystem-type-magic → name resolution (`0xEF53` → `"ext4"`) — the
  kernel's magic-number table is long and grows; `Usage.fs_type_magic` is
  exposed raw and a caller compares against the specific constant it needs.
- `/proc/mounts`/`mountinfo` for a namespace other than the caller's own
  (`/proc/<pid>/mounts` for another process) — only `self` is covered.
- `x32` ABI `statfs64` layout — refused at compile time
  (`statfs.zig`'s `family` dispatch) rather than guessed at; not a target of
  this collection.
