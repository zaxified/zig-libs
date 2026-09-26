# std.fs - File System API Reference (0.16)

File system operations in Zig 0.16. Covers files, directories, iteration, atomic writes, and paths.

**0.16 change:** almost everything that used to live under `std.fs` moved to `std.Io.Dir` / `std.Io.File`, and nearly every method now takes an `io: Io` argument (obtained from an `Io` implementation, e.g. `var threaded: std.Io.Threaded = .init(gpa, .{}); const io = threaded.io();`), because the actual read/write/open syscalls go through it. Only `std.fs.path` (pure path-string manipulation, no I/O) is unchanged.

## Table of Contents
- [Module Structure](#module-structure)
- [Working with Files](#working-with-files)
- [Working with Directories](#working-with-directories)
- [Directory Iteration](#directory-iteration)
- [Atomic File Operations](#atomic-file-operations)
- [Path Manipulation](#path-manipulation)
- [Common Patterns](#common-patterns)

## Module Structure

```zig
std.Io.File      // File handle and I/O operations (was std.fs.File)
std.Io.Dir       // Directory handle and operations (was std.fs.Dir)
std.Io.File.Atomic // Safe file writes with atomic rename/replace (was std.fs.AtomicFile)
std.fs.path      // Path manipulation utilities (unchanged, pure functions)
std.Io.Dir.cwd() // Current working directory handle (was std.fs.cwd())
```

## Working with Files

### Opening Files

```zig
// Open existing file for reading
const file = try std.Io.Dir.cwd().openFile(io, "data.txt", .{});
defer file.close(io);

// Open with write access
const file = try std.Io.Dir.cwd().openFile(io, "data.txt", .{ .mode = .read_write });

// Create or truncate file
const file = try std.Io.Dir.cwd().createFile(io, "output.txt", .{});
defer file.close(io);

// Create without truncating existing
const file = try std.Io.Dir.cwd().createFile(io, "output.txt", .{ .truncate = false });

// Create exclusively (fail if exists)
const file = try std.Io.Dir.cwd().createFile(io, "new.txt", .{ .exclusive = true });
```

**OpenFlags** (`Dir.OpenFileOptions`):
- `.mode`: `.read_only` (default), `.write_only`, `.read_write`
- `.lock`: `.none`, `.shared`, `.exclusive` (advisory locking)
- `.lock_nonblocking`: return `error.WouldBlock` instead of waiting

**CreateFlags** (`Dir.CreateFileOptions`):
- `.read`: enable read access (default: false)
- `.truncate`: truncate if exists (default: true)
- `.exclusive`: fail if exists (default: false)
- `.mode`: POSIX mode (default: 0o666)

### Reading Files

```zig
const file = try std.Io.Dir.cwd().openFile(io, "data.txt", .{});
defer file.close(io);

var buf: [4096]u8 = undefined;
var reader = file.reader(io, &buf);

// Read lines
while (reader.interface.takeDelimiterExclusive('\n')) |line| {
    // process line (does not include '\n')
} else |err| switch (err) {
    error.EndOfStream => {},
    else => return err,
}

// Read all into buffer (limit is `Io.Limit`, not a bare `usize`)
const content = try reader.interface.allocRemaining(allocator, .limited(max_size));
defer allocator.free(content);
```

### Writing Files

```zig
const file = try std.Io.Dir.cwd().createFile(io, "output.txt", .{});
defer file.close(io);

var buf: [4096]u8 = undefined;
var writer = file.writer(io, &buf);
const w = &writer.interface;

try w.print("Line {d}\n", .{42});
try w.writeAll("Raw bytes\n");
try w.flush();  // REQUIRED - flushes buffer to file
```

### Convenience Methods

```zig
// Read entire file into a caller-provided buffer
var buffer: [4096]u8 = undefined;
const content = try std.Io.Dir.cwd().readFile(io, "data.txt", &buffer);

// Read with allocation (limit is `Io.Limit`)
const content = try std.Io.Dir.cwd().readFileAlloc(io, "data.txt", allocator, .limited(max_size));
defer allocator.free(content);

// Write entire contents
try std.Io.Dir.cwd().writeFile(io, .{
    .sub_path = "output.txt",
    .data = "Hello, World!",
});
```

### File Metadata

```zig
const stat = try file.stat(io);
stat.size;      // u64 - file size in bytes
stat.kind;      // .file, .directory, .sym_link, etc.
stat.mtime;     // Io.Timestamp - modification time
stat.atime;     // Io.Timestamp - access time
stat.ctime;     // Io.Timestamp - status change time
stat.inode;     // file system inode number

// Check if terminal
if (try file.isTty(io)) { ... }
```

**Note (0.16):** `file.getEndPos()` is gone — use `stat.size`. `stat.mode` is gone from the cross-platform `Stat`; use `stat.permissions` (`File.Permissions`).

### Seeking

**Note (0.16):** `File` itself has no `seekTo`/`seekBy`/`getPos` anymore — those live on the buffered `File.Reader` / `File.Writer` you get from `file.reader(io, buf)` / `file.writer(io, buf)`:

```zig
var buf: [4096]u8 = undefined;
var reader = file.reader(io, &buf);

try reader.seekTo(0);             // absolute position
try reader.seekBy(-100);          // relative to current
const pos = reader.logicalPos();  // current logical position
```

For direct random access without a stream, use `file.readPositional(io, buffers, offset)` / `file.writePositional(io, buffers, offset)`, which take an explicit byte offset per call.

### Standard I/O

```zig
const stdin = std.Io.File.stdin();
const stdout = std.Io.File.stdout();
const stderr = std.Io.File.stderr();

var buf: [4096]u8 = undefined;
var writer = stdout.writer(io, &buf);
try writer.interface.print("Hello\n", .{});
try writer.interface.flush();
```

## Working with Directories

### Opening Directories

```zig
// Open for file operations (default)
var dir = try std.Io.Dir.cwd().openDir(io, "subdir", .{});
defer dir.close(io);

// Open for iteration
var dir = try std.Io.Dir.cwd().openDir(io, "subdir", .{ .iterate = true });
defer dir.close(io);
```

**OpenOptions**:
- `.access_sub_paths`: can use as base for file ops (default: true)
- `.iterate`: can iterate contents (default: false)

### Creating Directories

```zig
// Create single directory (was makeDir)
try std.Io.Dir.cwd().createDir(io, "new_dir", .default_dir);

// Create with all parents (was makePath)
try std.Io.Dir.cwd().createDirPath(io, "path/to/nested/dir");

// Create and open (was makeOpenPath)
var dir = try std.Io.Dir.cwd().createDirPathOpen(io, "path/to/dir", .{});
defer dir.close(io);
```

### Deleting

```zig
// Delete file
try dir.deleteFile(io, "file.txt");

// Delete empty directory
try dir.deleteDir(io, "empty_dir");

// Delete recursively (files and subdirs)
try dir.deleteTree(io, "dir_with_contents");
```

### Renaming and Copying

```zig
// Rename within same directory
try dir.rename(io, "old.txt", "new.txt");

// Rename across directories — Dir.rename(old_dir, old_sub_path, new_dir, new_sub_path, io)
try std.Io.Dir.rename(old_dir, "file.txt", new_dir, "file.txt", io);

// Copy file atomically — Dir.copyFile(src_dir, src_path, dest_dir, dest_path, io, options)
try std.Io.Dir.copyFile(src_dir, "source.txt", dest_dir, "dest.txt", io, .{});

// Update only if source is newer — Dir.updateFile(src_dir, io, src_path, dest_dir, dest_path, options)
const status = try std.Io.Dir.updateFile(src_dir, io, "src.txt", dest_dir, "dst.txt", .{});
if (status == .stale) {
    // file was copied
}
```

### Checking Existence

```zig
// Check if accessible (TOCTOU warning!)
dir.access(io, "file.txt", .{}) catch |err| switch (err) {
    error.FileNotFound => { /* doesn't exist */ },
    else => return err,
};

// Better: just try to open and handle error
const file = dir.openFile(io, "file.txt", .{}) catch |err| switch (err) {
    error.FileNotFound => { /* handle missing */ return; },
    else => return err,
};
defer file.close(io);
```

## Directory Iteration

### Basic Iteration

```zig
var dir = try std.Io.Dir.cwd().openDir(io, ".", .{ .iterate = true });
defer dir.close(io);

var iter = dir.iterate();
while (try iter.next(io)) |entry| {
    std.debug.print("{s} ({s})\n", .{ entry.name, @tagName(entry.kind) });
}
```

**Entry.Kind** (`std.Io.File.Kind`): `.file`, `.directory`, `.sym_link`, `.block_device`, `.character_device`, `.named_pipe`, `.unix_domain_socket`, `.unknown`

### Recursive Walking

```zig
var dir = try std.Io.Dir.cwd().openDir(io, "src", .{ .iterate = true });
defer dir.close(io);

var walker = try dir.walk(allocator);
defer walker.deinit();

while (try walker.next(io)) |entry| {
    // entry.path: full relative path "subdir/file.txt"
    // entry.basename: just filename "file.txt"
    // entry.kind: file type
    // entry.dir: containing directory handle

    if (entry.kind == .file and std.mem.endsWith(u8, entry.basename, ".zig")) {
        std.debug.print("Found: {s}\n", .{entry.path});
    }
}
```

**Note (0.16):** `iterate()`/`walk()` build the iterator without touching `io` (no syscalls yet); `io` is only needed on each `.next(io)` call. There is no `iterator.reset()` anymore — open a fresh iterator with `dir.iterate()` instead.

## Atomic File Operations

Safe file writes using temporary files and atomic rename/replace. Prevents partial writes on crash. `dir.atomicFile(...)` is gone — it is now `dir.createFileAtomic(io, sub_path, options)`, returning a `std.Io.File.Atomic` (the buffer is no longer part of the options; build your own buffered writer from `atomic.file`):

```zig
var atomic = try dir.createFileAtomic(io, "output.txt", .{ .replace = true });
defer atomic.deinit(io);  // always call, even after link()/replace()

var buf: [4096]u8 = undefined;
var file_writer = atomic.file.writer(io, &buf);
const w = &file_writer.interface;
try w.print("Safe content\n", .{});
try w.flush();

try atomic.replace(io);  // atomically replace an existing file
// or: try atomic.link(io);  // fail with error.PathAlreadyExists if something is already there
```

**CreateFileAtomicOptions**:
- `.permissions`: permissions for the new file (default: `.default_file`)
- `.make_path`: create parent directories if missing
- `.replace`: must be `true` if you intend to call `atomic.replace()` instead of `atomic.link()`

## Path Manipulation

`std.fs.path` is unchanged in 0.16 — pure string manipulation, no I/O:

```zig
const path = std.fs.path;

// Join path components
const full = try path.join(allocator, &.{ "dir", "subdir", "file.txt" });
defer allocator.free(full);

// Split into directory and basename
const dir_part = path.dirname("/foo/bar/file.txt");   // "/foo/bar"
const base = path.basename("/foo/bar/file.txt");      // "file.txt"

// Get extension
const ext = path.extension("file.tar.gz");  // ".gz"
const stem = path.stem("file.tar.gz");      // "file.tar"

// Check if absolute
if (path.isAbsolute(p)) { ... }

// Resolve relative paths
const resolved = try path.resolve(allocator, &.{ base_dir, relative_path });
defer allocator.free(resolved);

// Platform-specific separator
const sep = path.sep;  // '/' on POSIX, '\\' on Windows
```

## Common Patterns

### Process All Files in Directory

```zig
var dir = try std.Io.Dir.cwd().openDir(io, "data", .{ .iterate = true });
defer dir.close(io);

var iter = dir.iterate();
while (try iter.next(io)) |entry| {
    if (entry.kind != .file) continue;

    var file = try dir.openFile(io, entry.name, .{});
    defer file.close(io);
    // process file...
}
```

### Safe Config File Update

```zig
fn saveConfig(io: std.Io, dir: std.Io.Dir, config: Config) !void {
    var atomic = try dir.createFileAtomic(io, "config.json", .{ .replace = true });
    defer atomic.deinit(io);

    var buf: [4096]u8 = undefined;
    var file_writer = atomic.file.writer(io, &buf);
    const w = &file_writer.interface;
    try std.json.Stringify.value(config, .{}, w);
    try w.flush();
    try atomic.replace(io);
}
```

### Find Files Recursively

```zig
fn findFiles(io: std.Io, allocator: Allocator, dir: std.Io.Dir, extension: []const u8) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (results.items) |s| allocator.free(s);
        results.deinit(allocator);
    }

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.basename, extension)) {
            const copy = try allocator.dupe(u8, entry.path);
            try results.append(allocator, copy);
        }
    }
    return try results.toOwnedSlice(allocator);
}
```

### Copy Directory Tree

```zig
fn copyTree(io: std.Io, allocator: Allocator, src: std.Io.Dir, dest: std.Io.Dir) !void {
    var walker = try src.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind == .directory) {
            try dest.createDirPath(io, entry.path);
        } else if (entry.kind == .file) {
            if (std.fs.path.dirname(entry.path)) |parent| {
                try dest.createDirPath(io, parent);
            }
            try std.Io.Dir.copyFile(entry.dir, entry.basename, dest, entry.path, io, .{});
        }
    }
}
```

### Read/Modify/Write Pattern

```zig
// Read existing content
const content = try dir.readFileAlloc(io, "data.txt", allocator, .limited(max_size));
defer allocator.free(content);

// Modify
const modified = try process(allocator, content);
defer allocator.free(modified);

// Write back atomically
var atomic = try dir.createFileAtomic(io, "data.txt", .{ .replace = true });
defer atomic.deinit(io);
var buf: [4096]u8 = undefined;
var file_writer = atomic.file.writer(io, &buf);
try file_writer.interface.writeAll(modified);
try file_writer.interface.flush();
try atomic.replace(io);
```
