# std.process - Process Management API Reference

Process spawning, environment variables, argument parsing, and system utilities in Zig 0.16.

## Table of Contents
- [Module Structure](#module-structure)
- [Spawning Child Processes](#spawning-child-processes)
- [Environment Variables](#environment-variables)
- [Command Line Arguments](#command-line-arguments)
- [Process Utilities](#process-utilities)
- [Common Patterns](#common-patterns)

## Module Structure

0.16 restructured `std.process` around three "handle" types plus a set of free
functions that take an `Io`:

```zig
std.process.Child         // Child process management (spawn, wait, kill)
std.process.Args          // Command-line arguments (a handle, obtained from main's parameter)
std.process.Environ       // Environment access (a handle); Environ.Map is the mutable hash map
std.process.Init          // Type of main's first parameter (bundles io/gpa/arena/args/environ)

std.process.exit          // Exit process immediately
std.process.abort         // Abort with core dump
std.process.fatal         // Log an error and exit(1)
std.process.currentPath   // Get current working directory (needs an Io)
std.process.replace       // Replace the current process image (needs an Io)
std.process.totalSystemMemory
```

Two things changed compared to older Zig:

- **`Args` and `Environ` are no longer fetched by free functions.** There is no
  `argsAlloc`, `argsWithAllocator`, `getEnvMap`, or `getEnvVarOwned` anymore.
  Instead they flow in through `main`'s parameter (see below). `EnvMap` is now
  `std.process.Environ.Map`; `ArgIterator` is now `std.process.Args.Iterator`.
- **Functions that touch the OS take an `Io`** (`currentPath`, `replace`,
  `executablePath`, `posixGetUserInfo`, …) — the same `Io`-threading pattern used
  by the child-process and networking APIs.

### Getting `Io`, an allocator, args, and the environment

Declare `main` to take a `std.process.Init` parameter. It bundles everything the
process needs, already initialized by the startup code:

```zig
pub fn main(init: std.process.Init) !void {
    const io = init.io;                    // std.Io
    const gpa = init.gpa;                  // std.mem.Allocator (leak-checked in Debug)
    const arena = init.arena.allocator();  // process-lifetime arena
    const environ = init.minimal.environ;  // std.process.Environ
    const env_map = init.environ_map;      // *std.process.Environ.Map (already populated)
    const args = init.minimal.args;        // std.process.Args
    _ = .{ io, gpa, arena, environ, env_map, args };
}
```

For a lighter entry point that only needs args and env (no `Io`/allocators
pre-built), take `std.process.Init.Minimal` instead — it has just `.args` and
`.environ`. The examples below assume `io`, `gpa`, `args`, and `environ` came from
`main`'s `Init` as above.

## Spawning Child Processes

Every child-process operation needs an `Io` instance. Create one once (typically in
`main`) and thread it through — the same pattern the networking APIs use:

```zig
var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();   // io: std.Io
```

The examples below assume `io` (an `std.Io`) and `gpa` / `allocator` (an
`std.mem.Allocator`) are already in scope.

### Basic Spawn and Wait

```zig
var child = try std.process.spawn(io, .{
    .argv = &.{ "ls", "-la" },
    .cwd = .{ .path = "/tmp" },  // optional; defaults to .inherit
});
const term = try child.wait(io);

switch (term) {
    .exited => |code| std.debug.print("Exited with {d}\n", .{code}),
    // .signal / .stopped carry a std.posix.SIG enum — get the number via @intFromEnum
    .signal => |sig| std.debug.print("Killed by signal {d}\n", .{@intFromEnum(sig)}),
    .stopped => |sig| std.debug.print("Stopped by signal {d}\n", .{@intFromEnum(sig)}),
    .unknown => |status| std.debug.print("Unknown status {d}\n", .{status}),
}
```

`std.process.spawn` takes `std.process.SpawnOptions`; `argv` is the only required
field. It returns a `std.process.Child`. `child.wait(io)` blocks until the child
exits, returns its `Term`, and cleans up its resources.

### Capture Output

```zig
const result = try std.process.run(gpa, io, .{
    .argv = &.{ "git", "status", "--short" },
    .cwd = .{ .path = project_dir },   // optional
    // .stdout_limit / .stderr_limit default to .unlimited
});
defer gpa.free(result.stdout);
defer gpa.free(result.stderr);

if (result.term == .exited and result.term.exited == 0) {
    std.debug.print("Output: {s}\n", .{result.stdout});
} else {
    std.debug.print("Error: {s}\n", .{result.stderr});
}
```

`std.process.run` (formerly `Child.run`) spawns the process with stdout/stderr piped,
waits, and collects both streams into a `RunResult`. The caller owns `result.stdout`
and `result.stderr`.

### Pipe to/from Child

```zig
var child = try std.process.spawn(io, .{
    .argv = &.{"cat"},
    .stdin = .pipe,
    .stdout = .pipe,
});

// Write to the child's stdin, then close it so the child sees EOF.
var wbuf: [64]u8 = undefined;
var stdin_writer = child.stdin.?.writer(io, &wbuf);
try stdin_writer.interface.writeAll("Hello from parent\n");
try stdin_writer.interface.flush();
child.stdin.?.close(io);
child.stdin = null;

// Read everything the child wrote to stdout.
var rbuf: [4096]u8 = undefined;
var stdout_reader = child.stdout.?.reader(io, &rbuf);
const out = try stdout_reader.interface.allocRemaining(gpa, .unlimited);
defer gpa.free(out);

const term = try child.wait(io);
_ = term;
```

When a stream's `StdIo` is `.pipe`, the matching `child.stdin` / `child.stdout` /
`child.stderr` field is populated with a `File`. Get an `Io.Writer` / `Io.Reader` from
it via `file.writer(io, buf)` / `file.reader(io, buf)` and use the `.interface`.

### StdIo Behaviors

`SpawnOptions.stdin`, `.stdout`, and `.stderr` each take a
`std.process.SpawnOptions.StdIo` — a `union(enum)` with lowercase members:

```zig
.stdin = .inherit,               // share the parent's stream (default)
.stdin = .pipe,                  // create a pipe; child.stdin becomes a File
.stdin = .ignore,                // /dev/null (NUL on Windows)
.stdin = .close,                 // close the stream (advanced; child may hit EBADF)
.stdin = .{ .file = some_file },  // pass an already-open File to the child

// Same options apply to .stdout and .stderr.
```

### Spawn with Custom Environment

```zig
var env = std.process.Environ.Map.init(gpa);
defer env.deinit();
try env.put("PATH", "/usr/bin:/bin");
try env.put("MY_VAR", "value");

var child = try std.process.spawn(io, .{
    .argv = &.{"my_program"},
    .environ_map = &env,
});
_ = try child.wait(io);
```

The env-map type is `std.process.Environ.Map` (formerly `std.process.EnvMap`).

### Set Working Directory

`SpawnOptions.cwd` is a `Child.Cwd` union: `.inherit` (default), `.{ .path = ... }`,
or `.{ .dir = ... }`.

```zig
// Option 1: path string
var c1 = try std.process.spawn(io, .{
    .argv = &.{"make"},
    .cwd = .{ .path = "/path/to/project" },
});
_ = try c1.wait(io);

// Option 2: directory handle
var dir = try std.Io.Dir.cwd().openDir(io, "project", .{});
defer dir.close(io);
var c2 = try std.process.spawn(io, .{
    .argv = &.{"make"},
    .cwd = .{ .dir = dir },
});
_ = try c2.wait(io);
```

### Kill Child Process

```zig
var child = try std.process.spawn(io, .{ .argv = &.{ "sleep", "100" } });

// ... later
child.kill(io);  // force-terminates, waits, and cleans up (returns void)
```

`child.kill(io)` is idempotent and does nothing after `wait` has already returned.

### Resource Usage Statistics

```zig
var child = try std.process.spawn(io, .{
    .argv = &.{"heavy_computation"},
    .request_resource_usage_statistics = true,
});
_ = try child.wait(io);

if (child.resource_usage_statistics.getMaxRss()) |rss| {
    std.debug.print("Peak memory: {d} bytes\n", .{rss});
}
```

### POSIX-only: Change User/Group

Set `uid` / `gid` / `pgid` directly in `SpawnOptions` (the `setUserName` helper was
removed):

```zig
var child = try std.process.spawn(io, .{
    .argv = &.{"daemon"},
    .uid = 65534,
    .gid = 65534,
    .pgid = 0,  // create a new process group
});
_ = try child.wait(io);
```

### Windows-only Options

```zig
var child = try std.process.spawn(io, .{
    .argv = &.{"app.exe"},
    .create_no_window = true,  // hide console window
    .start_suspended = true,   // start paused
});
_ = try child.wait(io);
```

### Darwin-only: Disable ASLR

```zig
var child = try std.process.spawn(io, .{
    .argv = &.{"debugee"},
    .disable_aslr = true,
});
_ = try child.wait(io);
```

## Environment Variables

Environment access goes through `std.process.Environ` (the `environ` handle from
`main`'s `Init`). The old free functions (`getEnvVarOwned`, `getEnvMap`,
`hasEnvVarConstant`, `hasEnvVar`, `hasNonEmptyEnvVarConstant`, `parseEnvVarInt`)
are all gone.

### Get Single Variable

```zig
// Borrowed lookup — no allocation, valid for the process lifetime.
// The full Init already parsed the environment into env_map (*Environ.Map).
if (init.environ_map.get("HOME")) |home| {
    std.debug.print("HOME={s}\n", .{home});
}

// Owned copy from the raw Environ (caller frees). Returns
// error.EnvironmentVariableMissing if the variable is not set.
const home = environ.getAlloc(gpa, "HOME") catch |err| switch (err) {
    error.EnvironmentVariableMissing => "/tmp",  // or handle however you like
    else => return err,
};
// (free `home` with gpa only if it came from getAlloc)

// No-allocation POSIX lookup straight from the environment block.
if (environ.getPosix("HOME")) |h| {
    std.debug.print("HOME={s}\n", .{h});
}
```

### Check Existence

```zig
// Compile-time-known key, no allocation.
if (environ.containsConstant("DEBUG")) {
    // DEBUG is set
}

// Set and non-empty.
if (environ.containsUnemptyConstant("PATH")) {
    // PATH is set and not empty
}

// Dynamic key (allocates a temporary map internally).
const has_it = try environ.contains(gpa, key);
```

There is no built-in "parse env var as int" helper anymore; fetch the string and
parse it yourself with `std.fmt.parseInt`.

### Get / Iterate All Variables

```zig
// The full Init already gives you a populated map; just iterate it.
var it = init.environ_map.iterator();
while (it.next()) |entry| {
    std.debug.print("{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
}

// Or build your own owned snapshot from an Environ (e.g. under Init.Minimal):
var map = try environ.createMap(gpa);
defer map.deinit();
if (map.get("PATH")) |path| {
    std.debug.print("PATH={s}\n", .{path});
}
```

### Environ.Map Operations

`std.process.Environ.Map` (formerly `std.process.EnvMap`) is a mutable env hash
map — use it to build a custom environment for a child process.

```zig
var env = std.process.Environ.Map.init(gpa);
defer env.deinit();

// Add/update (copies key and value)
try env.put("KEY", "value");

// Add/update (takes ownership, avoids copy)
const key_owned = try gpa.dupe(u8, "KEY2");
const val_owned = try gpa.dupe(u8, "value2");
try env.putMove(key_owned, val_owned);  // env now owns both

// Lookup
const value = env.get("KEY");       // ?[]const u8
const ptr = env.getPtr("KEY");      // ?*[]const u8
_ = .{ value, ptr };

// Remove (returns whether an entry was removed). There is no plain `remove`:
_ = env.swapRemove("KEY");    // fast; reorders the map
_ = env.orderedRemove("KEY"); // preserves insertion order

// Count
const n = env.count();
_ = n;
```

**Note**: On Windows, environment variable names are case-insensitive.
`Environ.Map` handles this automatically.

## Command Line Arguments

Arguments arrive as a `std.process.Args` handle via `main`'s `Init`
(`init.minimal.args`). The old top-level entry points (`argsWithAllocator`,
`argsAlloc`, `argsFree`, `ArgIterator`, `ArgIteratorGeneral`) are gone; iterate the
`Args` handle instead.

### POSIX Iterator (no allocation)

```zig
var it = args.iterate();
_ = it.skip();   // skip program name

while (it.next()) |arg| {   // arg: [:0]const u8
    std.debug.print("arg: {s}\n", .{arg});
}
```

`args.iterate()` is the no-allocation path but is **POSIX-only** — it fails to
compile on Windows and WASI.

### Cross-platform Iterator

```zig
// Required on Windows/WASI (they must decode/allocate); works everywhere.
var it = try args.iterateAllocator(gpa);
defer it.deinit();

_ = it.skip();
while (it.next()) |arg| {
    std.debug.print("arg: {s}\n", .{arg});
}
```

### Get All Arguments as a Slice

`toSlice` needs an **arena** (the result references several allocations and may
point into the args block), so pass an arena allocator such as
`init.arena.allocator()`:

```zig
const argv = try args.toSlice(arena);   // []const [:0]const u8

const program = argv[0];
for (argv[1..]) |arg| {
    // process arg
}
```

### Parse Response Files (shell-style)

`IteratorGeneral` moved under `std.process.Args`:

```zig
const ArgParser = std.process.Args.IteratorGeneral(.{
    .comments = true,       // skip # comments
    .single_quotes = true,  // support 'quoted args'
});

var parser = try ArgParser.init(gpa, response_file_content);
defer parser.deinit();

while (parser.next()) |arg| {
    // process arg
}
```

## Process Utilities

### Current Working Directory

CWD access now takes an `Io`. `getCwd` / `getCwdAlloc` were renamed to
`currentPath` / `currentPathAlloc`.

```zig
// Into a provided buffer; returns the number of bytes written.
var buf: [std.fs.max_path_bytes]u8 = undefined;
const n = try std.process.currentPath(io, &buf);
const cwd = buf[0..n];
_ = cwd;

// With allocation (caller frees). Returns a sentinel-terminated [:0]u8.
const cwd_owned = try std.process.currentPathAlloc(io, gpa);
defer gpa.free(cwd_owned);
```

Change the working directory with `setCurrentPath` (by path) or `setCurrentDir`
(by open directory handle):

```zig
try std.process.setCurrentPath(io, "/tmp");

var dir = try std.Io.Dir.cwd().openDir(io, ".", .{});
defer dir.close(io);
try std.process.setCurrentDir(io, dir);
```

### Exit Process

```zig
// Clean success exit. In Debug it is a no-op (so cleanup/leak checks still run);
// in release it flushes stderr and calls exit(0). Needs an Io.
std.process.cleanExit(io);

// Immediate exit with code
std.process.exit(0);   // success
std.process.exit(1);   // failure

// Abort (generates core dump on POSIX)
std.process.abort();

// Log an error via std.log and exit(1) (replaces the old "print + exit" idiom)
std.process.fatal("bad config value: {d}", .{code});
```

### Replace Current Process

`execv` / `execve` were replaced by `replace` (resolves `argv[0]` via `PATH`) and
`replacePath` (treats `argv[0]` as a path relative to a directory). Both take an
`Io`. On success they never return; they only return on failure, and the return
value **is** the error (the return type is `ReplaceError`, an error set), so there
is no `try`:

```zig
// Only reached on failure; err is the ReplaceError value.
const err = std.process.replace(io, .{
    .argv = &.{ "/bin/sh", "-c", "echo hello" },
});
std.log.err("exec failed: {t}", .{err});
return err;

// With a custom environment and a resolved directory:
var env = std.process.Environ.Map.init(gpa);
defer env.deinit();
try env.put("PATH", "/bin");

var dir = try std.Io.Dir.cwd().openDir(io, "/bin", .{});
defer dir.close(io);
return std.process.replacePath(io, dir, .{
    .argv = &.{ "echo", "hi" },
    .environ_map = &env,
});
```

`std.process.can_replace` is `false` on Windows, Haiku, and WASI (there, `replace`
returns `error.OperationUnsupported`).

### System Memory

```zig
const total = try std.process.totalSystemMemory();
std.debug.print("Total RAM: {d} bytes\n", .{total});
```

### User Information (POSIX only)

> **Broken in 0.16.0.** Both `std.process.getUserInfo(name)` and
> `std.process.posixGetUserInfo(io, name)` fail to compile in the 0.16.0 standard
> library (internal call-site bugs: `getUserInfo` calls `posixGetUserInfo` with
> the wrong argument count, and `posixGetUserInfo` calls `File.reader` with the
> wrong argument count). There is currently no working public idiom. The intended
> signature is `posixGetUserInfo(io, name) !UserInfo` returning
> `.{ .uid, .gid }`; until it is fixed upstream, read and parse `/etc/passwd`
> yourself if you need this. Watch for a fix in a later 0.16.x release.

### Raise File Descriptor Limit

```zig
// Attempt to raise the NOFILE limit (no-op on unsupported platforms)
std.process.raiseFileDescriptorLimit();
```

### Executable Path

```zig
// Allocated (caller frees). Returns a sentinel-terminated [:0]u8.
const exe = try std.process.executablePathAlloc(io, gpa);
defer gpa.free(exe);

// Into a buffer; returns the number of bytes written.
var buf: [std.fs.max_path_bytes]u8 = undefined;
const n = try std.process.executablePath(io, &buf);
const path = buf[0..n];
_ = path;
```

### Check Capabilities

```zig
if (std.process.can_spawn) {
    // std.process.spawn / run are supported
}

if (std.process.can_replace) {
    // std.process.replace / replacePath are supported
}
```

## Common Patterns

### Run Command and Check Success

```zig
fn runCommand(gpa: Allocator, io: std.Io, argv: []const []const u8) !void {
    const result = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("Command failed:\n{s}\n", .{result.stderr});
        return error.CommandFailed;
    }
}
```

### Pipe Between Processes

```zig
fn pipeCommands(gpa: Allocator, io: std.Io) ![]u8 {
    // First command produces output on a pipe.
    var producer = try std.process.spawn(io, .{
        .argv = &.{ "echo", "hello world" },
        .stdout = .pipe,
    });

    // Hand the producer's stdout straight to the consumer as its stdin.
    var consumer = try std.process.spawn(io, .{
        .argv = &.{ "tr", "a-z", "A-Z" },
        .stdin = .{ .file = producer.stdout.? },
        .stdout = .pipe,
    });
    // The parent no longer needs its copy of the producer's read end.
    producer.stdout.?.close(io);
    producer.stdout = null;

    // Collect the consumer's output.
    var buf: [4096]u8 = undefined;
    var reader = consumer.stdout.?.reader(io, &buf);
    const out = try reader.interface.allocRemaining(gpa, .unlimited);

    _ = try producer.wait(io);
    _ = try consumer.wait(io);

    return out;
}
```

### Environment Variable Fallback Chain

`environ` is the `std.process.Environ` from `main`'s `Init`; `getAlloc` returns an
owned copy or `error.EnvironmentVariableMissing`.

```zig
fn getConfigPath(gpa: Allocator, environ: std.process.Environ) ![]const u8 {
    // Try a specific var first.
    if (environ.getAlloc(gpa, "MY_APP_CONFIG")) |path| {
        return path;
    } else |_| {}

    // Fall back to XDG.
    if (environ.getAlloc(gpa, "XDG_CONFIG_HOME")) |xdg| {
        defer gpa.free(xdg);
        return std.fs.path.join(gpa, &.{ xdg, "myapp", "config.json" });
    } else |_| {}

    // Fall back to HOME.
    const home = try environ.getAlloc(gpa, "HOME");
    defer gpa.free(home);
    return std.fs.path.join(gpa, &.{ home, ".config", "myapp", "config.json" });
}
```

### Process Pool / Parallel Execution

```zig
fn runParallel(gpa: Allocator, io: std.Io, commands: []const []const []const u8) !void {
    var children: std.ArrayList(std.process.Child) = .empty;
    defer children.deinit(gpa);

    // Start all processes.
    for (commands) |argv| {
        const child = try std.process.spawn(io, .{ .argv = argv });
        try children.append(gpa, child);
    }

    // Wait for all.
    for (children.items) |*child| {
        const term = try child.wait(io);
        if (term != .exited or term.exited != 0) {
            return error.ChildFailed;
        }
    }
}
```

### Argument Parsing with Flags

```zig
pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var args = init.minimal.args.iterate();
    _ = args.skip(); // skip program name

    var verbose = false;
    var output: ?[]const u8 = null;
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(gpa);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "-o")) {
            output = args.next() orelse return error.MissingOutputArg;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return error.InvalidArgument;
        } else {
            try positional.append(gpa, arg);
        }
    }

    // Use the parsed arguments.
    std.debug.print("verbose={} output={?s} positional={d}\n", .{
        verbose, output, positional.items.len,
    });
}
```

### Spawn with Timeout

There is no non-blocking term poll in 0.16 (`child.term` is gone). Instead, use
`std.process.run`'s `timeout` field — it kills the child and returns `error.Timeout`
if the child outlives the deadline:

```zig
fn runWithTimeout(gpa: Allocator, io: std.Io, argv: []const []const u8) !std.process.RunResult {
    return std.process.run(gpa, io, .{
        .argv = argv,
        // error.Timeout if the child runs longer than 5 seconds.
        .timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } },
    });
    // On success the caller owns result.stdout / result.stderr.
}
```

`RunOptions.timeout` is an `std.Io.Timeout` (`.none`, `.{ .duration = ... }`, or
`.{ .deadline = ... }`). A `Clock.Duration` is `{ .raw = <std.Io.Duration>, .clock =
<Clock> }`; `.awake` is the monotonic clock.
