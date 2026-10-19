# std.tar - Tar Archive API Reference

Tar archive reading and writing in Zig 0.17.0. Supports POSIX ustar, GNU extensions for long names, and pax extended headers.

## Table of Contents
- [Module Structure](#module-structure)
- [Reading Tar Archives](#reading-tar-archives)
- [Extracting to Filesystem](#extracting-to-filesystem)
- [Writing Tar Archives](#writing-tar-archives)
- [Diagnostics and Error Handling](#diagnostics-and-error-handling)
- [Common Patterns](#common-patterns)

## Module Structure

```zig
std.tar.Iterator    // Iterate over entries in tar archive
std.tar.Writer      // Create tar archives
std.tar.Diagnostics // Collect errors during extraction
std.tar.FileKind    // .file, .directory, .sym_link
std.tar.ExtractOptions // Options for extract (was PipeOptions)
std.tar.extract()  // Extract archive to directory (was pipeToFileSystem before 0.17)
```

## Reading Tar Archives

### Iterator API

Iterate over files, directories, and symlinks in a tar archive:

```zig
const data = @embedFile("archive.tar");
var reader: std.Io.Reader = .fixed(data);

// Buffers must be provided by caller
var file_name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
var link_name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;

var it: std.tar.Iterator = .init(&reader, .{
    .file_name_buffer = &file_name_buffer,
    .link_name_buffer = &link_name_buffer,
});

while (try it.next()) |file| {
    switch (file.kind) {
        .directory => std.debug.print("Dir: {s}\n", .{file.name}),
        .file => {
            std.debug.print("File: {s} ({d} bytes)\n", .{ file.name, file.size });
            // Read file content - see below
        },
        .sym_link => std.debug.print("Link: {s} -> {s}\n", .{ file.name, file.link_name }),
    }
}
```

### Iterator.File Structure

```zig
pub const File = struct {
    name: []const u8,      // file/dir/symlink path
    link_name: []const u8, // symlink target (empty for files/dirs)
    size: u64,             // file size in bytes
    mode: u32,             // POSIX permission mode
    kind: FileKind,        // .file, .directory, .sym_link
};
```

### Reading File Contents

File content must be read before calling `next()` again:

```zig
while (try it.next()) |file| {
    if (file.kind == .file) {
        // Option 1: Stream to writer (file.name must be validated first, see "Untrusted archive" below)
        var buf: [1024]u8 = undefined;
        const output_file = try dir.createFile(io, file.name, .{});
        defer output_file.close(io);
        var file_writer = output_file.writer(io, &buf);
        try it.streamRemaining(file, &file_writer.interface);
        try file_writer.interface.flush();

        // Option 2: Stream to allocated buffer. file.size comes from the archive: cap it first
        if (file.size > 64 * 1024 * 1024) return error.FileTooLarge;
        var content: std.Io.Writer.Allocating = .init(allocator);
        defer content.deinit();
        try it.streamRemaining(file, &content.writer);
        const bytes = content.written();  // []const u8
    }
}
```

**Untrusted archive:** `file.name` comes from the archive and may contain `..` or be absolute (zip-slip). Validate it (no `..` component, not absolute) before using it as a path. `std.tar.extract` does **not** make an archive safe: it sanitizes entry *names* only (`sanitizePath`, `lib/std/tar.zig:676-705`), while a symlink entry's target (`file.link_name`) goes unchecked into `dir.symLink` (`tar.zig:634-636, 664-674`), and files are created without `resolve_beneath`. An archive with `x -> /some/abs/dir` followed by `x/file` therefore writes outside the destination. For untrusted input use the iterator, reject `.sym_link` entries, validate names, and extract into a fresh empty directory (compiled and run on 0.17.0):

```zig
fn nameIsSafe(name: []const u8) bool {
    // Conservative on purpose: `\` and `:` are rejected too, so the check also holds on
    // Windows (`..\x`, `\x`, `C:\x`, UNC `\\host\share`); it refuses legal POSIX names with those bytes.
    if (name.len == 0 or name[0] == '/' or std.mem.findAny(u8, name, "\\:\x00") != null) return false;
    var parts = std.mem.splitScalar(u8, name, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn extractUntrusted(io: std.Io, dest: std.Io.Dir, reader: *std.Io.Reader) !void {
    var name_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(reader, .{
        .file_name_buffer = &name_buf,
        .link_name_buffer = &link_buf,
    });
    while (try it.next()) |entry| {
        if (!nameIsSafe(entry.name)) return error.UnsafeTarEntry;
        switch (entry.kind) {
            .sym_link => return error.SymlinkInUntrustedTar, // or skip it
            .directory => try dest.createDirPath(io, entry.name),
            .file => {
                if (std.Io.Dir.path.dirname(entry.name)) |parent| try dest.createDirPath(io, parent);
                const out = try dest.createFile(io, entry.name, .{ .exclusive = true });
                defer out.close(io);
                var wbuf: [4096]u8 = undefined;
                var fw = out.writer(io, &wbuf);
                try it.streamRemaining(entry, &fw.interface);
                try fw.interface.flush();
            },
        }
    }
}
```

### Iterator Options

```zig
pub const Options = struct {
    file_name_buffer: []u8,     // buffer for file paths (use max_path_bytes)
    link_name_buffer: []u8,     // buffer for symlink targets
    diagnostics: ?*Diagnostics, // optional error collection
};
```

## Extracting to Filesystem

### extract

Extract entire archive to a directory. **Trusted archives only**: names are sanitized but symlink targets are not (see "Untrusted archive" above for the safe pattern):

```zig
const data = @embedFile("archive.tar");
var reader: std.Io.Reader = .fixed(data);

try std.tar.extract(io, std.Io.Dir.cwd(), &reader, .{
    .strip_components = 1,        // remove leading path component
    .mode_mode = .executable_bit_only,
    .exclude_empty_directories = false,
});
```

### From File

```zig
const file = try std.Io.Dir.cwd().openFile(io, "archive.tar", .{});
defer file.close(io);

var buf: [4096]u8 = undefined;
var file_reader = file.reader(io, &buf);

try std.tar.extract(io, output_dir, &file_reader.interface, .{});
```

### ExtractOptions

```zig
pub const ExtractOptions = struct {
    strip_components: u32 = 0,  // directories to strip from paths
    mode_mode: ModeMode = .executable_bit_only,
    exclude_empty_directories: bool = false,
    diagnostics: ?*Diagnostics = null,

    pub const ModeMode = enum {
        ignore,              // ignore tar mode, use system defaults
        executable_bit_only, // copy only executable bit to group/other
    };
};
```

**strip_components**: Removes leading path components. `strip_components = 1` converts `archive/src/main.zig` to `src/main.zig`.

**mode_mode**:
- `.ignore`: All files created with default permissions
- `.executable_bit_only`: If owner has execute bit, set it for group and other too

## Writing Tar Archives

### Writer API

```zig
var output: std.Io.Writer.Allocating = .init(allocator);
defer output.deinit();

var w: std.tar.Writer = .{ .underlying_writer = &output.writer };

// Optional: set root directory prefix
try w.setRoot("myproject");

// Write files
try w.writeFileBytes("README.md", "# My Project\n", .{});
try w.writeFileBytes("src/main.zig", source_code, .{ .mode = 0o644 });

// Write directory
try w.writeDir("data", .{});

// Write symlink
try w.writeLink("latest", "v1.0", .{});

// Get tar data
const tar_bytes = output.written();
```

### Writing from File

```zig
const output_file = try std.Io.Dir.cwd().createFile(io, "archive.tar", .{});
defer output_file.close(io);
var buf: [4096]u8 = undefined;
var file_writer = output_file.writer(io, &buf);

var w: std.tar.Writer = .{ .underlying_writer = &file_writer.interface };

// Write file from disk
const src_file = try std.Io.Dir.cwd().openFile(io, "data.txt", .{});
defer src_file.close(io);
var src_buf: [4096]u8 = undefined;
var src_reader = src_file.reader(io, &src_buf);
const stat = try src_file.stat(io);
// Stat.mtime is `Io.Timestamp` (nanoseconds); writeFile wants POSIX seconds.
// i96 -> u96 -> u64, each step range-checked (signed -> narrower unsigned @intCast: #37131)
const secs = @divTrunc(stat.mtime.nanoseconds, std.time.ns_per_s);
const mtime_secs: u64 = std.math.cast(u64, std.math.cast(u96, secs) orelse 0) orelse 0;

try w.writeFile("data.txt", &src_reader, mtime_secs);

try file_writer.interface.flush();
```

### Writing from Stream

```zig
// When you know the size upfront
var content_reader: std.Io.Reader = .fixed(content_bytes);
try w.writeFileStream("file.txt", content_bytes.len, &content_reader, .{});
```

### Writer Methods

```zig
// Set prefix for all subsequent paths
pub fn setRoot(w: *Writer, root: []const u8) Error!void

// Write directory entry
pub fn writeDir(w: *Writer, sub_path: []const u8, options: Options) Error!void

// Write file from bytes
pub fn writeFileBytes(w: *Writer, sub_path: []const u8, content: []const u8, options: Options) Error!void

// Write file from reader with known size
pub fn writeFileStream(w: *Writer, sub_path: []const u8, size: u64, reader: *std.Io.Reader, options: Options) WriteFileStreamError!void

// Write file from file reader
pub fn writeFile(w: *Writer, sub_path: []const u8, file_reader: *std.Io.File.Reader, mtime: u64) WriteFileError!void

// Same, taking the file's Io.Timestamp (converted to POSIX seconds)
pub fn writeFileTimestamp(w: *Writer, sub_path: []const u8, file_reader: *std.Io.File.Reader, mtime: std.Io.Timestamp) WriteFileError!void

// Write symbolic link
pub fn writeLink(w: *Writer, sub_path: []const u8, link_name: []const u8, options: Options) Error!void

// Write two zero blocks (optional, per spec)
pub fn finishPedantically(w: *Writer) std.Io.Writer.Error!void
```

### Writer Options

```zig
pub const Options = struct {
    mode: u32 = 0,   // POSIX mode (0 = default: 0o664 for files)
    mtime: u64 = 0,  // modification time (0 = current time)
};
```

## Diagnostics and Error Handling

### Using Diagnostics

Collect errors instead of failing immediately:

```zig
var diagnostics: std.tar.Diagnostics = .{ .allocator = allocator };
defer diagnostics.deinit();

std.tar.extract(io, dir, &reader, .{
    .diagnostics = &diagnostics,
}) catch |err| {
    // Some errors are still fatal
    return err;
};

// Check collected errors
for (diagnostics.errors.items) |item| {
    switch (item) {
        .unable_to_create_file => |info| {
            std.debug.print("Failed to create {s}: {}\n", .{ info.file_name, info.code });
        },
        .unable_to_create_sym_link => |info| {
            std.debug.print("Failed to link {s} -> {s}\n", .{ info.file_name, info.link_name });
        },
        .unsupported_file_type => |info| {
            std.debug.print("Unsupported: {s} (type {})\n", .{ info.file_name, info.file_type });
        },
        .components_outside_stripped_prefix => |info| {
            std.debug.print("Stripped: {s}\n", .{info.file_name});
        },
    }
}

// Diagnostics also tracks root directory discovery
std.debug.print("Root dir: {s}, entries: {d}\n", .{ diagnostics.root_dir, diagnostics.entries });
```

### Diagnostics.Error Types

```zig
pub const Error = union(enum) {
    unable_to_create_sym_link: struct {
        code: anyerror,
        file_name: []const u8,
        link_name: []const u8,
    },
    unable_to_create_file: struct {
        code: anyerror,
        file_name: []const u8,
    },
    unsupported_file_type: struct {
        file_name: []const u8,
        file_type: Header.Kind,
    },
    components_outside_stripped_prefix: struct {
        file_name: []const u8,
    },
};
```

## Common Patterns

### Extract and Process Archive

```zig
fn extractTar(io: std.Io, allocator: Allocator, tar_data: []const u8, dest: std.Io.Dir) !void {
    var reader: std.Io.Reader = .fixed(tar_data);

    var diagnostics: std.tar.Diagnostics = .{ .allocator = allocator };
    defer diagnostics.deinit();

    try std.tar.extract(io, dest, &reader, .{
        .strip_components = 1,
        .diagnostics = &diagnostics,
    });

    if (diagnostics.errors.items.len > 0) {
        for (diagnostics.errors.items) |err| {
            std.log.warn("tar extraction issue: {}", .{err});
        }
    }
}
```

### List Archive Contents

```zig
fn listTar(allocator: Allocator, tar_data: []const u8) !void {
    _ = allocator;
    var reader: std.Io.Reader = .fixed(tar_data);

    var file_name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;

    var it: std.tar.Iterator = .init(&reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (try it.next()) |file| {
        const kind_char: u8 = switch (file.kind) {
            .directory => 'd',
            .file => '-',
            .sym_link => 'l',
        };
        std.debug.print("{c} {o:0>4} {d:>10} {s}", .{
            kind_char, file.mode, file.size, file.name,
        });
        if (file.kind == .sym_link) {
            std.debug.print(" -> {s}", .{file.link_name});
        }
        std.debug.print("\n", .{});
    }
}
```

### Create Archive from Directory

```zig
fn createTarFromDir(io: std.Io, allocator: Allocator, source_dir: std.Io.Dir, root_name: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();

    var w: std.tar.Writer = .{ .underlying_writer = &output.writer };
    try w.setRoot(root_name);

    var walker = try source_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        switch (entry.kind) {
            .directory => try w.writeDir(entry.path, .{}),
            .file => {
                const file = try entry.dir.openFile(io, entry.basename, .{});
                defer file.close(io);
                var buf: [4096]u8 = undefined;
                var file_reader = file.reader(io, &buf);
                const stat = try file.stat(io);
                const secs = @divTrunc(stat.mtime.nanoseconds, std.time.ns_per_s);
                const mtime_secs: u64 = std.math.cast(u64, std.math.cast(u96, secs) orelse 0) orelse 0; // #37131
                try w.writeFile(entry.path, &file_reader, mtime_secs);
            },
            .sym_link => {
                var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
                const len = try entry.dir.readLink(io, entry.basename, &link_buf);
                try w.writeLink(entry.path, link_buf[0..len], .{});
            },
            else => {},  // skip special files
        }
    }

    return output.toOwnedSlice();
}
```

### Extract Single File

```zig
fn extractFile(tar_data: []const u8, target_name: []const u8, allocator: Allocator) !?[]u8 {
    var reader: std.Io.Reader = .fixed(tar_data);

    var file_name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;

    var it: std.tar.Iterator = .init(&reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (try it.next()) |file| {
        if (file.kind == .file and std.mem.eql(u8, file.name, target_name)) {
            // file.size comes from the archive: cap it before allocating
            if (file.size > 64 * 1024 * 1024) return error.FileTooLarge;
            var content: std.Io.Writer.Allocating = .init(allocator);
            errdefer content.deinit();
            try it.streamRemaining(file, &content.writer);
            return try content.toOwnedSlice();
        }
    }
    return null;
}
```

## Supported Features

**Formats**: POSIX ustar, GNU long name/link extensions, pax extended headers

**Entry types**: Regular files, directories, symbolic links

**Not supported**: Hard links, device nodes, FIFOs, sparse files (logged via diagnostics)

**Path handling**: Automatic prefix/name splitting, GNU extended headers for paths > 256 bytes
