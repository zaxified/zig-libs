// SPDX-License-Identifier: MIT
//! MCP Skills (the `io.modelcontextprotocol/skills` extension, SEP-2640): a
//! server publishes Agent Skills (agentskills.io) as resources. The
//! TypeScript SDK 2.4.0 `SkillsExtension` (`load(files)` → a catalog,
//! `attach(server)`, `loadSkills(folder)`) does the same; here it is
//! `Catalog.load` / `Catalog.loadDir` and `Catalog.attach` over the building
//! blocks the server already has (`Server.addMethod`,
//! `Server.addResourceTemplate`, `Server.setCapabilityExtras`).
//!
//! Wire shapes (ext-skills `specification/beta/skills.mdx`, against base
//! revision 2026-07-28):
//!   - every file of a skill directory is a resource `skill://<skill-path>/<file>`,
//!     read with `resources/read` (served here through the template
//!     `skill://{+path}`); a skill is addressed by the uri of its `SKILL.md`;
//!   - `skills/list` (paginated) and `skills/get` answer `Skill` entries: the
//!     uri, the `SKILL.md` YAML frontmatter as a JSON object, and the complete
//!     manifest of the skill's files with `sha256:` digests and sizes (or
//!     `"dynamic"` for a generated skill);
//!   - `resources/directory/read` (when `directoryRead` is declared) lists the
//!     direct children of a directory resource (`inode/directory`);
//!   - the server advertises `capabilities.extensions["io.modelcontextprotocol/skills"]`
//!     and, because skills are resources, `capabilities.resources`.
//!   - On a 2026-07-28 request the three results carry `ttlMs`/`cacheScope`
//!     (`Server.list_cache` for the two listings, `Server.read_cache` for
//!     `skills/get`); a session-era request gets none, as in the TS SDK.
//!
//! A skill that breaks the format (no frontmatter, bad YAML, a `name` that is
//! not the directory's name or not `[a-z0-9-]`, a missing `description`, more
//! than 512 files or 16 MiB) is left out and reported in `Catalog.skipped`, or
//! refused with `error.InvalidSkill` under `Options.strict` — the TS SDK's
//! `onWarning` / `strict`. A file whose bytes are valid UTF-8 is served as
//! `text`, any other as a base64 `blob` (TS: the same rule).
//!
//! Not here: the host side (verification, approval, the acting window) — this
//! module is a server.

const std = @import("std");
const yaml = @import("yaml");
const root = @import("root.zig");

/// The extension's identifier, reserved by the spec.
pub const extension_id = "io.modelcontextprotocol/skills";
/// The uri scheme skills are served under.
pub const uri_scheme = "skill://";
/// The file that makes a directory a skill.
pub const skill_file = "SKILL.md";
/// The mime type of a directory resource.
pub const directory_mime_type = "inode/directory";
/// The uri template the files are served through (RFC 6570 reserved expansion).
pub const uri_template = "skill://{+path}";
/// Per-skill limits every conforming host accepts (spec "Limits"); a skill
/// over either is not served (SHOULD NOT).
pub const max_resources_per_skill: usize = 512;
pub const max_skill_bytes: u64 = 16 * 1024 * 1024;
/// Agent Skills field limits.
pub const max_name_len = 64;
pub const max_description_len = 1024;
/// Frontmatter nesting cap: a custom method's result is re-parsed under
/// `root.max_json_depth` (128), and an entry sits four levels deep.
pub const max_frontmatter_depth = 64;
/// Values and bytes of the frontmatter once written as JSON (aliases expanded).
pub const max_frontmatter_nodes = 10_000;
pub const max_frontmatter_json_bytes = 256 * 1024;

/// One file of the skill namespace.
pub const File = struct {
    /// `/`-separated path inside the namespace: `acme/billing/refunds/SKILL.md`.
    /// No empty, `.` or `..` segment, no leading or trailing `/`.
    path: []const u8,
    bytes: []const u8,
    /// "" = chosen by `mimeTypeFor`.
    mime_type: []const u8 = "",
};

/// A generated skill (TS `SkillSource`): its entry carries
/// `"resources":"dynamic"`, its `SKILL.md` is `skill_md`, and every other read
/// under its directory goes to `read`. It is reached through `skills/list` and
/// `skills/get` only: it has no directory resources.
pub const Dynamic = struct {
    /// The skill path (`reports/daily`); its last segment is the skill's name.
    path: []const u8,
    /// The `SKILL.md` text: served as is, and the frontmatter's source.
    skill_md: []const u8,
    /// Reads of other uris under the skill's directory; null = there are none.
    read: ?root.ResourceHandler = null,
    ctx: ?*anyopaque = null,
};

pub const Options = struct {
    /// Refuse the whole catalog (`error.InvalidSkill`) instead of leaving a
    /// broken skill out.
    strict: bool = false,
    /// Declare `directoryRead` and serve `resources/directory/read`.
    directory_read: bool = true,
    /// Under `strict`: receives the skill that failed.
    diagnostic: ?*Diagnostic = null,
};

/// The skill that made a `strict` load fail. Owns a copy of the path
/// (truncated past `path_buf.len`), so it outlives the failed load.
pub const Diagnostic = struct {
    problem: Problem = undefined,
    path_buf: [512]u8 = undefined,
    path_len: usize = 0,

    pub fn path(self: *const Diagnostic) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    fn set(self: *Diagnostic, p: []const u8, problem: Problem) void {
        self.path_len = @min(p.len, self.path_buf.len);
        @memcpy(self.path_buf[0..self.path_len], p[0..self.path_len]);
        self.problem = problem;
    }
};

/// Why a skill was left out.
pub const Problem = enum {
    /// `SKILL.md` does not begin with a `---` frontmatter block.
    no_frontmatter,
    /// The frontmatter is not YAML this module accepts (or is too deep/large).
    bad_yaml,
    /// The frontmatter is not a mapping.
    frontmatter_not_mapping,
    /// A key that is not a string, or a float JSON cannot carry (inf, nan).
    unrepresentable_value,
    /// The frontmatter as JSON would be deeper than `max_frontmatter_depth`,
    /// hold more than `max_frontmatter_nodes` values or `max_frontmatter_json_bytes`
    /// bytes — YAML aliases share nodes, so a few lines can expand without
    /// bound ("billion laughs").
    frontmatter_too_large,
    /// `name` missing or not a string.
    missing_name,
    /// `name` breaks the Agent Skills rules (1–64 of `a-z0-9-`, no edge or double hyphen).
    bad_name,
    /// `name` is not the last segment of the skill's path.
    name_mismatch,
    /// `description` missing or not a string.
    missing_description,
    /// `description` empty or over 1024 characters.
    bad_description,
    /// `SKILL.md` at the namespace root: a skill needs a directory.
    no_directory,
    /// More than `max_resources_per_skill` files.
    too_many_files,
    /// More than `max_skill_bytes` in all (or a file `loadDir` could not hold).
    too_large,
};

pub const Skipped = struct {
    /// The skill path (`""` for a root `SKILL.md`).
    path: []const u8,
    problem: Problem,
};

pub const LoadError = error{
    OutOfMemory,
    /// Two files with one path.
    DuplicatePath,
    /// A path with an empty, `.` or `..` segment, a leading/trailing `/`, or
    /// bytes that are not UTF-8.
    BadPath,
    /// One path is a file and also a directory of another file (`a/x` and
    /// `a/x/y`): they would share one uri.
    PathConflict,
    /// A dynamic skill whose directory holds a static file or another skill,
    /// or lies inside a static skill (the enclosing manifest could not be complete).
    OverlappingDynamicSkill,
    /// `Options.strict` and a skill broke the format (see `Options.diagnostic`).
    InvalidSkill,
};

pub const AttachError = error{
    OutOfMemory,
    /// The catalog is already attached, or the server already declares the extension.
    AlreadyAttached,
    InvalidCapabilityJson,
} || root.Server.MethodError || error{DuplicateResourceTemplate};

/// One served skill.
pub const Skill = struct {
    /// The skill path (`acme/billing/refunds`).
    path: []const u8,
    /// The uri of its `SKILL.md`.
    uri: []const u8,
    name: []const u8,
    description: []const u8,
    /// The frontmatter as one JSON object.
    frontmatter_json: []const u8,
    /// Its files (indices into the catalog's file table, sorted by path);
    /// null for a dynamic skill.
    files: ?[]const u32,
    dynamic: ?Dynamic = null,
};

const StoredFile = struct {
    path: []const u8,
    uri: []const u8,
    bytes: []const u8,
    mime_type: []const u8,
    digest: [71]u8,
    text: bool,
};

const Dir = struct {
    path: []const u8,
    uri: []const u8,
};

const State = struct {
    arena: std.heap.ArenaAllocator,
    files: []StoredFile = &.{},
    by_uri: std.StringHashMapUnmanaged(u32) = .empty,
    skills: []Skill = &.{},
    skipped: []Skipped = &.{},
    dirs: []Dir = &.{},

    fn destroy(st: *State, gpa: std.mem.Allocator) void {
        st.arena.deinit();
        gpa.destroy(st);
    }
};

/// A set of skills ready to be served. `attach` keeps a pointer to it: keep
/// the `Catalog` at one address, alive as long as the server.
pub const Catalog = struct {
    gpa: std.mem.Allocator,
    options: Options,
    state: *State,
    ext_json: []u8 = &.{},
    attached: bool = false,

    /// Build a catalog from in-memory files (copied) and generated skills
    /// (borrowed: their slices and `ctx` must outlive the catalog).
    pub fn load(gpa: std.mem.Allocator, files: []const File, dynamic: []const Dynamic, options: Options) LoadError!Catalog {
        return .{ .gpa = gpa, .options = options, .state = try build(gpa, files, &.{}, dynamic, options, true) };
    }

    pub const DirError = LoadError || std.Io.Dir.Iterator.Error || std.Io.Dir.ReadFileAllocError || std.Io.Dir.OpenError;

    /// Build a catalog from a directory tree (TS `loadSkills(folder)`). Entries
    /// whose name starts with `.` are skipped, symbolic links are not followed,
    /// and a file over `max_skill_bytes` makes its skills `too_large`.
    /// `dir` must be opened with `.iterate = true`.
    pub fn loadDir(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, dynamic: []const Dynamic, options: Options) DirError!Catalog {
        return .{ .gpa = gpa, .options = options, .state = try buildFromDir(gpa, io, dir, dynamic, options) };
    }

    pub fn deinit(self: *Catalog) void {
        self.state.destroy(self.gpa);
        if (self.ext_json.len != 0) self.gpa.free(self.ext_json);
        self.* = undefined;
    }

    /// Replace the catalog's contents (TS `reload()`); on error the old ones
    /// stay. Call it under the same lock as `Server.handleMessage`.
    pub fn reload(self: *Catalog, files: []const File, dynamic: []const Dynamic) LoadError!void {
        const st = try build(self.gpa, files, &.{}, dynamic, self.options, true);
        self.state.destroy(self.gpa);
        self.state = st;
    }

    /// `reload` from a directory tree (see `loadDir`).
    pub fn reloadDir(self: *Catalog, io: std.Io, dir: std.Io.Dir, dynamic: []const Dynamic) DirError!void {
        const st = try buildFromDir(self.gpa, io, dir, dynamic, self.options);
        self.state.destroy(self.gpa);
        self.state = st;
    }

    /// The served skills, sorted by path.
    pub fn skills(self: *const Catalog) []const Skill {
        return self.state.skills;
    }

    /// The skills left out, and why.
    pub fn skipped(self: *const Catalog) []const Skipped {
        return self.state.skipped;
    }

    /// The skill whose `SKILL.md` is `uri`.
    pub fn find(self: *const Catalog, uri: []const u8) ?*const Skill {
        for (self.state.skills) |*s| if (std.mem.eql(u8, s.uri, uri)) return s;
        return null;
    }

    /// The `capabilities.extensions` entry value for these options.
    pub fn settingsJson(self: *const Catalog) []const u8 {
        return if (self.options.directory_read) "{\"directoryRead\":true}" else "{}";
    }

    /// Serve the catalog from `server`: `skills/list`, `skills/get`,
    /// `resources/directory/read` (with `directory_read`), the `skill://{+path}`
    /// template, and the extension in `capabilities.extensions` (merged with
    /// what the server already declares).
    ///
    /// All or nothing: on an error the server is left as it was. Call it
    /// after every `Server.setCapabilityExtras` — that call replaces the
    /// extensions object, so a later one would drop the skills declaration
    /// while the methods stay registered.
    pub fn attach(self: *Catalog, server: *root.Server) AttachError!void {
        if (self.attached) return error.AlreadyAttached;
        const names = [_][]const u8{ "skills/list", "skills/get", "resources/directory/read" };
        const handlers = [_]root.MethodHandler{ handleList, handleGet, handleDirRead };
        const n_methods: usize = if (self.options.directory_read) 3 else 2;
        // Every refusal first, before anything is registered (the merge has
        // no side effects, and names an already declared extension first).
        const merged = try mergeExtensions(self.gpa, server.extensions_json, self.settingsJson());
        errdefer self.gpa.free(merged);
        for (server.custom_methods.items) |m| for (names[0..n_methods]) |n| {
            if (std.mem.eql(u8, m.name, n)) return error.DuplicateMethod;
        };
        for (server.resource_templates.items) |t| {
            if (std.mem.eql(u8, t.uri_template, uri_template)) return error.DuplicateResourceTemplate;
        }
        // Registration: only OOM can fail now, and each step is undone.
        const methods_before = server.custom_methods.items.len;
        errdefer server.custom_methods.shrinkRetainingCapacity(methods_before);
        for (names[0..n_methods], handlers[0..n_methods]) |n, h|
            try server.addMethod(.{ .name = n, .handler = h, .ctx = self });
        try server.addResourceTemplate(.{
            .uri_template = uri_template,
            .name = "skills",
            .description = "Agent Skills files (" ++ extension_id ++ ")",
            .handler = handleRead,
            .ctx = self,
        });
        errdefer _ = server.removeResourceTemplate(uri_template);
        try server.setCapabilityExtras(merged, server.experimental_json);
        if (self.ext_json.len != 0) self.gpa.free(self.ext_json);
        self.ext_json = merged;
        self.attached = true;
    }
};

fn mergeExtensions(gpa: std.mem.Allocator, existing: []const u8, settings: []const u8) AttachError![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    const w = &aw.writer;
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    write: {
        w.writeByte('{') catch break :write;
        if (existing.len != 0) {
            const v = std.json.parseFromSliceLeaky(std.json.Value, scratch.allocator(), existing, .{}) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidCapabilityJson,
            };
            if (v != .object) return error.InvalidCapabilityJson;
            if (v.object.get(extension_id) != null) return error.AlreadyAttached;
            var it = v.object.iterator();
            while (it.next()) |e| {
                std.json.Stringify.value(e.key_ptr.*, .{}, w) catch break :write;
                w.writeByte(':') catch break :write;
                std.json.Stringify.value(e.value_ptr.*, .{}, w) catch break :write;
                w.writeByte(',') catch break :write;
            }
        }
        w.writeAll("\"" ++ extension_id ++ "\":") catch break :write;
        w.writeAll(settings) catch break :write;
        w.writeByte('}') catch break :write;
        return aw.toOwnedSlice() catch error.OutOfMemory;
    }
    return error.OutOfMemory; // an allocating writer fails only on OOM
}

// ── loading ─────────────────────────────────────────────────────────────────

fn checkPath(path: []const u8) LoadError!void {
    if (path.len == 0 or !std.unicode.utf8ValidateSlice(path)) return error.BadPath;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return error.BadPath;
    }
}

/// A uri byte kept as is: RFC 3986 unreserved, the sub-delims, `:`, `@` and
/// the `/` separator (RFC 6570 `{+path}` keeps the reserved set; `?`, `#`,
/// `[`, `]` and `%` are encoded here so the result stays one path).
fn keepInUri(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '/' => true,
        else => false,
    };
}

/// The first segment is the uri's authority: a reg-name (RFC 3986 §3.2.2,
/// spec SHOULD), so `:` and `@` are encoded there too.
fn keepAt(path: []const u8, i: usize, first_slash: usize) bool {
    const c = path[i];
    if (i < first_slash and (c == ':' or c == '@')) return false;
    return keepInUri(c);
}

fn uriFor(arena: std.mem.Allocator, path: []const u8) error{OutOfMemory}![]u8 {
    const first_slash = std.mem.findScalar(u8, path, '/') orelse path.len;
    var n: usize = uri_scheme.len;
    for (0..path.len) |i| n += if (keepAt(path, i, first_slash)) 1 else 3;
    const out = try arena.alloc(u8, n);
    @memcpy(out[0..uri_scheme.len], uri_scheme);
    var i: usize = uri_scheme.len;
    const hex = "0123456789ABCDEF";
    for (path, 0..) |c, ci| {
        if (keepAt(path, ci, first_slash)) {
            out[i] = c;
            i += 1;
        } else {
            out[i] = '%';
            out[i + 1] = hex[c >> 4];
            out[i + 2] = hex[c & 15];
            i += 3;
        }
    }
    return out;
}

/// A mime type from the file's extension (`SKILL.md` and other `.md` are
/// `text/markdown`); unknown text is `text/plain`, unknown binary
/// `application/octet-stream`.
pub fn mimeTypeFor(path: []const u8, bytes_are_text: bool) []const u8 {
    const base = if (std.mem.findScalarLast(u8, path, '/')) |i| path[i + 1 ..] else path;
    const dot = std.mem.findScalarLast(u8, base, '.') orelse return if (bytes_are_text) "text/plain" else "application/octet-stream";
    const ext = base[dot + 1 ..];
    const table = [_]struct { []const u8, []const u8 }{
        .{ "md", "text/markdown" },      .{ "markdown", "text/markdown" },
        .{ "txt", "text/plain" },        .{ "json", "application/json" },
        .{ "yaml", "application/yaml" }, .{ "yml", "application/yaml" },
        .{ "py", "text/x-python" },      .{ "sh", "text/x-shellscript" },
        .{ "js", "text/javascript" },    .{ "mjs", "text/javascript" },
        .{ "ts", "text/typescript" },    .{ "html", "text/html" },
        .{ "htm", "text/html" },         .{ "css", "text/css" },
        .{ "csv", "text/csv" },          .{ "xml", "application/xml" },
        .{ "toml", "application/toml" }, .{ "png", "image/png" },
        .{ "jpg", "image/jpeg" },        .{ "jpeg", "image/jpeg" },
        .{ "gif", "image/gif" },         .{ "webp", "image/webp" },
        .{ "svg", "image/svg+xml" },     .{ "pdf", "application/pdf" },
        .{ "zip", "application/zip" },   .{ "wasm", "application/wasm" },
    };
    for (table) |e| if (std.ascii.eqlIgnoreCase(ext, e[0])) return e[1];
    return if (bytes_are_text) "text/plain" else "application/octet-stream";
}

fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;
    for (name, 0..) |c, i| switch (c) {
        'a'...'z', '0'...'9' => {},
        '-' => if (i > 0 and name[i - 1] == '-') return false,
        else => return false,
    };
    return true;
}

fn charCount(s: []const u8) usize {
    return std.unicode.utf8CountCodepoints(s) catch s.len;
}

const Front = struct { json: []const u8, name: []const u8, description: []const u8 };

/// The `---` block at the very start of `SKILL.md` (after an optional UTF-8
/// BOM, which the TS SDK client strips too), without its delimiters.
fn frontmatterText(md_in: []const u8) ?[]const u8 {
    const md = if (std.mem.startsWith(u8, md_in, "\xEF\xBB\xBF")) md_in[3..] else md_in;
    const first_end = std.mem.findScalar(u8, md, '\n') orelse return null;
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, md[0..first_end], "\r"), "---")) return null;
    var pos = first_end + 1;
    while (pos <= md.len) {
        const end = std.mem.findScalarPos(u8, md, pos, '\n') orelse md.len;
        if (std.mem.eql(u8, std.mem.trimEnd(u8, md[pos..end], "\r"), "---")) return md[first_end + 1 .. pos];
        if (end == md.len) break;
        pos = end + 1;
    }
    return null;
}

const FrontError = error{OutOfMemory} || error{Invalid};

fn parseFront(arena: std.mem.Allocator, gpa: std.mem.Allocator, md: []const u8, problem: *Problem) FrontError!Front {
    const text = frontmatterText(md) orelse {
        problem.* = .no_frontmatter;
        return error.Invalid;
    };
    const doc = yaml.compose(gpa, text, .{
        .max_depth = max_frontmatter_depth,
        .max_nodes = 100_000,
        .max_heap_bytes = 4 * 1024 * 1024,
        .schema = .core,
    }) catch |e| {
        if (e == error.OutOfMemory) return error.OutOfMemory;
        // No document (an empty block) or several: not one mapping.
        problem.* = if (e == error.ExpectedSingleDocument) .frontmatter_not_mapping else .bad_yaml;
        return error.Invalid;
    };
    defer doc.deinit();
    if (doc.root != .mapping) {
        problem.* = .frontmatter_not_mapping;
        return error.Invalid;
    }
    var aw: std.Io.Writer.Allocating = .init(arena);
    var jw: std.json.Stringify = .{ .writer = &aw.writer };
    var budget: Budget = .{ .aw = &aw };
    writeValue(&jw, doc.root, &budget, 1) catch |e| switch (e) {
        error.WriteFailed => return error.OutOfMemory,
        error.Unrepresentable => {
            problem.* = .unrepresentable_value;
            return error.Invalid;
        },
        error.TooLarge => {
            problem.* = .frontmatter_too_large;
            return error.Invalid;
        },
    };
    const name = doc.root.get("name") orelse .null;
    if (name != .string) {
        problem.* = .missing_name;
        return error.Invalid;
    }
    if (!validName(name.string)) {
        problem.* = .bad_name;
        return error.Invalid;
    }
    const description = doc.root.get("description") orelse .null;
    if (description != .string) {
        problem.* = .missing_description;
        return error.Invalid;
    }
    const dl = charCount(description.string);
    if (dl == 0 or dl > max_description_len) {
        problem.* = .bad_description;
        return error.Invalid;
    }
    return .{
        .json = aw.written(),
        .name = try arena.dupe(u8, name.string),
        .description = try arena.dupe(u8, description.string),
    };
}

/// The cost of writing one frontmatter: a composed YAML tree is a DAG
/// (aliases share nodes), so its JSON form is bounded here, not by `compose`.
const Budget = struct {
    aw: *std.Io.Writer.Allocating,
    nodes: usize = 0,

    fn take(b: *Budget, depth: usize) error{TooLarge}!void {
        b.nodes += 1;
        if (depth > max_frontmatter_depth or b.nodes > max_frontmatter_nodes or
            b.aw.written().len > max_frontmatter_json_bytes) return error.TooLarge;
    }
};

fn writeValue(jw: *std.json.Stringify, v: yaml.Value, budget: *Budget, depth: usize) (std.Io.Writer.Error || error{ Unrepresentable, TooLarge })!void {
    try budget.take(depth);
    switch (v) {
        .null => try jw.write(null),
        .bool => |b| try jw.write(b),
        .int => |i| try jw.write(i),
        .float => |f| {
            if (!std.math.isFinite(f)) return error.Unrepresentable;
            try jw.write(f);
        },
        .string => |s| try jw.write(s),
        .sequence => |items| {
            try jw.beginArray();
            for (items) |it| try writeValue(jw, it, budget, depth + 1);
            try jw.endArray();
        },
        .mapping => |pairs| {
            try jw.beginObject();
            for (pairs) |p| {
                if (p.key != .string) return error.Unrepresentable;
                try jw.objectField(p.key.string);
                try writeValue(jw, p.value, budget, depth + 1);
            }
            try jw.endObject();
        },
    }
}

fn lessFile(_: void, a: StoredFile, b: StoredFile) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

/// Is `path` inside directory `dir` (a strict descendant)?
fn under(path: []const u8, dir: []const u8) bool {
    return path.len > dir.len + 1 and std.mem.startsWith(u8, path, dir) and path[dir.len] == '/';
}

fn parentOf(path: []const u8) []const u8 {
    return if (std.mem.findScalarLast(u8, path, '/')) |i| path[0..i] else "";
}

fn lastSegment(path: []const u8) []const u8 {
    return if (std.mem.findScalarLast(u8, path, '/')) |i| path[i + 1 ..] else path;
}

fn buildFromDir(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, dynamic: []const Dynamic, options: Options) Catalog.DirError!*State {
    var scratch: std.heap.ArenaAllocator = .init(gpa);
    defer scratch.deinit();
    const a = scratch.allocator();
    var files: std.ArrayList(File) = .empty;
    var oversize: std.ArrayList([]const u8) = .empty;
    var walker = try dir.walkSelectively(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.basename.len != 0 and entry.basename[0] == '.') continue;
        switch (entry.kind) {
            .directory => try walker.enter(io, entry),
            .file => {
                const path = try a.dupe(u8, entry.path);
                if (std.fs.path.sep != '/') std.mem.replaceScalar(u8, path, std.fs.path.sep, '/');
                const bytes = entry.dir.readFileAlloc(io, entry.basename, a, .limited(max_skill_bytes + 1)) catch |e| switch (e) {
                    error.StreamTooLong => {
                        try oversize.append(a, path);
                        continue;
                    },
                    else => |x| return x,
                };
                try files.append(a, .{ .path = path, .bytes = bytes });
            },
            else => {}, // symbolic links, devices, sockets: not followed, not served
        }
    }
    return build(gpa, files.items, oversize.items, dynamic, options, true);
}

fn build(gpa: std.mem.Allocator, files_in: []const File, oversize: []const []const u8, dynamic: []const Dynamic, options: Options, copy: bool) LoadError!*State {
    const st = try gpa.create(State);
    st.* = .{ .arena = .init(gpa) };
    errdefer st.destroy(gpa);
    const a = st.arena.allocator();

    // Every file, validated, copied, digested, sorted by path.
    var all = try a.alloc(StoredFile, files_in.len);
    for (files_in, 0..) |f, i| {
        try checkPath(f.path);
        const path = try a.dupe(u8, f.path);
        const bytes = f.bytes; // copied below, once it is known to be served
        const text = std.unicode.utf8ValidateSlice(bytes);
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
        var digest: [71]u8 = undefined;
        @memcpy(digest[0..7], "sha256:");
        digest[7..].* = std.fmt.bytesToHex(d, .lower);
        all[i] = .{
            .path = path,
            .uri = try uriFor(a, path),
            .bytes = bytes,
            .mime_type = if (f.mime_type.len != 0) try a.dupe(u8, f.mime_type) else mimeTypeFor(path, text),
            .digest = digest,
            .text = text,
        };
    }
    std.mem.sort(StoredFile, all, {}, lessFile);
    if (all.len > 1) for (all[0 .. all.len - 1], all[1..]) |x, y| if (std.mem.eql(u8, x.path, y.path)) return error.DuplicatePath;
    for (oversize) |p| try checkPath(p);
    {
        var paths: std.StringHashMapUnmanaged(void) = .empty;
        for (all) |f| try paths.put(a, f.path, {});
        for (all) |f| {
            var p = parentOf(f.path);
            while (p.len != 0) : (p = parentOf(p)) if (paths.contains(p)) return error.PathConflict;
        }
    }

    var skipped: std.ArrayList(Skipped) = .empty;
    var found: std.ArrayList(Skill) = .empty;
    const skip = struct {
        fn f(list: *std.ArrayList(Skipped), alloc: std.mem.Allocator, opts: Options, path: []const u8, problem: Problem) LoadError!void {
            if (opts.strict) {
                if (opts.diagnostic) |d| d.set(path, problem);
                return error.InvalidSkill;
            }
            try list.append(alloc, .{ .path = path, .problem = problem });
        }
    }.f;

    // Static skills: every directory holding a SKILL.md.
    for (all) |f| {
        if (!std.mem.eql(u8, lastSegment(f.path), skill_file)) continue;
        const dir = parentOf(f.path);
        if (dir.len == 0) {
            try skip(&skipped, a, options, dir, .no_directory);
            continue;
        }
        var problem: Problem = undefined;
        const front = parseFront(a, gpa, f.bytes, &problem) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Invalid => {
                try skip(&skipped, a, options, dir, problem);
                continue;
            },
        };
        if (!std.mem.eql(u8, front.name, lastSegment(dir))) {
            try skip(&skipped, a, options, dir, .name_mismatch);
            continue;
        }
        var members: std.ArrayList(u32) = .empty;
        var total: u64 = 0;
        for (all, 0..) |g, i| if (under(g.path, dir)) {
            try members.append(a, @intCast(i));
            total += g.bytes.len;
        };
        var too_big = false;
        for (oversize) |p| if (under(p, dir)) {
            too_big = true;
        };
        if (members.items.len > max_resources_per_skill) {
            try skip(&skipped, a, options, dir, .too_many_files);
            continue;
        }
        if (too_big or total > max_skill_bytes) {
            try skip(&skipped, a, options, dir, .too_large);
            continue;
        }
        try found.append(a, .{
            .path = dir,
            .uri = f.uri,
            .name = front.name,
            .description = front.description,
            .frontmatter_json = front.json,
            .files = members.items,
        });
    }

    // Dynamic skills.
    for (dynamic, 0..) |d, di| {
        try checkPath(d.path);
        for (all) |f| if (under(f.path, d.path)) return error.OverlappingDynamicSkill;
        for (found.items) |s| if (s.dynamic == null and (under(d.path, s.path) or std.mem.eql(u8, d.path, s.path))) return error.OverlappingDynamicSkill;
        for (dynamic[0..di]) |o| if (under(d.path, o.path) or under(o.path, d.path) or std.mem.eql(u8, o.path, d.path)) return error.OverlappingDynamicSkill;
        var problem: Problem = undefined;
        const front = parseFront(a, gpa, d.skill_md, &problem) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Invalid => {
                try skip(&skipped, a, options, d.path, problem);
                continue;
            },
        };
        if (!std.mem.eql(u8, front.name, lastSegment(d.path))) {
            try skip(&skipped, a, options, d.path, .name_mismatch);
            continue;
        }
        const path = try a.dupe(u8, d.path);
        const md_path = try std.mem.concat(a, u8, &.{ path, "/", skill_file });
        try found.append(a, .{
            .path = path,
            .uri = try uriFor(a, md_path),
            .name = front.name,
            .description = front.description,
            .frontmatter_json = front.json,
            .files = null,
            .dynamic = d,
        });
    }
    std.mem.sort(Skill, found.items, {}, struct {
        fn lt(_: void, x: Skill, y: Skill) bool {
            return std.mem.lessThan(u8, x.path, y.path);
        }
    }.lt);

    // Served files: those inside a served static skill. Re-index the skills.
    var served: std.ArrayList(StoredFile) = .empty;
    const remap = try a.alloc(u32, all.len);
    for (all, 0..) |f, i| {
        remap[i] = std.math.maxInt(u32);
        for (found.items) |s| if (s.dynamic == null and under(f.path, s.path)) {
            remap[i] = @intCast(served.items.len);
            var kept = f;
            if (copy) kept.bytes = try a.dupe(u8, f.bytes);
            try served.append(a, kept);
            break;
        };
    }
    for (found.items) |*s| if (s.files) |members| {
        const fixed = try a.alloc(u32, members.len);
        for (members, fixed) |m, *o| o.* = remap[m];
        s.files = fixed;
    };
    for (served.items, 0..) |f, i| try st.by_uri.put(a, f.uri, @intCast(i));

    // Directory resources: every ancestor directory of a served file.
    var dirs: std.ArrayList(Dir) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    for (served.items) |f| {
        var p = parentOf(f.path);
        while (p.len != 0) : (p = parentOf(p)) {
            const gop = try seen.getOrPut(a, p);
            if (gop.found_existing) break;
            try dirs.append(a, .{ .path = p, .uri = try uriFor(a, p) });
        }
    }
    std.mem.sort(Dir, dirs.items, {}, struct {
        fn lt(_: void, x: Dir, y: Dir) bool {
            return std.mem.lessThan(u8, x.path, y.path);
        }
    }.lt);

    st.files = served.items;
    st.skills = found.items;
    st.skipped = skipped.items;
    st.dirs = dirs.items;
    return st;
}

// ── serving ─────────────────────────────────────────────────────────────────

/// Opaque page cursor: base64url-nopad of `<tag>:<scope>:<start>`, so one
/// listing's cursor is refused by another (scope = FNV-1a of the directory
/// uri for a directory read, 0 for `skills/list`).
fn cursor(arena: std.mem.Allocator, tag: u8, scope: u32, start: usize) error{OutOfMemory}![]const u8 {
    var buf: [48]u8 = undefined;
    const raw = std.mem.print(&buf, "{c}:{x}:{d}", .{ tag, scope, start }) catch unreachable; // fits: 1+1+8+1+20
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(raw.len));
    return enc.encode(out, raw);
}

fn decodeCursor(text: []const u8, tag: u8, scope: u32, len: usize) ?usize {
    var buf: [48]u8 = undefined;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const n = dec.calcSizeForSlice(text) catch return null;
    if (n > buf.len) return null;
    dec.decode(buf[0..n], text) catch return null;
    var it = std.mem.splitScalar(u8, buf[0..n], ':');
    const t = it.next() orelse return null;
    if (t.len != 1 or t[0] != tag) return null;
    const s = std.fmt.parseInt(u32, it.next() orelse return null, 16) catch return null;
    if (s != scope) return null;
    const start = std.fmt.parseInt(usize, it.next() orelse return null, 10) catch return null;
    if (it.next() != null or start > len) return null;
    return start;
}

const PageError = error{InvalidCursor};

fn pageStart(req: *root.MethodRequest, tag: u8, scope: u32, len: usize) PageError!usize {
    const s = req.server orelse return 0;
    if (s.page_size == 0) return 0; // pagination off: any cursor is ignored (as the base lists do)
    if (req.params != .object) return 0;
    const c = req.params.object.get("cursor") orelse return 0;
    return switch (c) {
        .null => 0,
        .string => |t| decodeCursor(t, tag, scope, len) orelse error.InvalidCursor,
        else => error.InvalidCursor,
    };
}

fn pageEnd(req: *const root.MethodRequest, start: usize, len: usize) usize {
    const size = if (req.server) |s| s.page_size else 0;
    return if (size == 0) len else @min(len, start +| size);
}

fn writeCache(jw: *std.json.Stringify, req: *const root.MethodRequest, hint: root.CacheHint) std.Io.Writer.Error!void {
    if (req.modern == null) return;
    try jw.objectField("ttlMs");
    try jw.write(hint.ttl_ms);
    try jw.objectField("cacheScope");
    try jw.write(@tagName(hint.scope));
}

fn writeEntry(jw: *std.json.Stringify, st: *const State, s: *const Skill) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("uri");
    try jw.write(s.uri);
    try jw.objectField("frontmatter");
    try jw.beginWriteRaw();
    try jw.writer.writeAll(s.frontmatter_json);
    jw.endWriteRaw();
    try jw.objectField("resources");
    if (s.files) |members| {
        try jw.beginArray();
        for (members) |m| {
            const f = &st.files[m];
            try jw.beginObject();
            try jw.objectField("uri");
            try jw.write(f.uri);
            try jw.objectField("digest");
            try jw.write(&f.digest);
            try jw.objectField("size");
            try jw.write(f.bytes.len);
            try jw.endObject();
        }
        try jw.endArray();
    } else {
        try jw.write("dynamic");
    }
    try jw.endObject();
}

fn catalogOf(ctx: ?*anyopaque) *const Catalog {
    return @ptrCast(@alignCast(ctx.?));
}

fn handleList(ctx: ?*anyopaque, req: *root.MethodRequest) bool {
    const st = catalogOf(ctx).state;
    const start = pageStart(req, 's', 0, st.skills.len) catch
        return req.failProtocol(root.error_code.invalid_params, "Invalid cursor", "");
    const end = pageEnd(req, start, st.skills.len);
    var aw: std.Io.Writer.Allocating = .init(req.arena);
    var jw: std.json.Stringify = .{ .writer = &aw.writer };
    writeList(&jw, req, st, start, end) catch return false; // OOM → -32603
    req.write(aw.written());
    return true;
}

fn writeList(jw: *std.json.Stringify, req: *const root.MethodRequest, st: *const State, start: usize, end: usize) (std.Io.Writer.Error || error{OutOfMemory})!void {
    try jw.beginObject();
    try jw.objectField("skills");
    try jw.beginArray();
    for (st.skills[start..end]) |*s| try writeEntry(jw, st, s);
    try jw.endArray();
    if (end < st.skills.len) {
        try jw.objectField("nextCursor");
        try jw.write(try cursor(req.arena, 's', 0, end));
    }
    try writeCache(jw, req, if (req.server) |s| s.list_cache else .{});
    try jw.endObject();
}

fn uriParam(req: *const root.MethodRequest) ?[]const u8 {
    if (req.params != .object) return null;
    const v = req.params.object.get("uri") orelse return null;
    return if (v == .string) v.string else null;
}

fn handleGet(ctx: ?*anyopaque, req: *root.MethodRequest) bool {
    const cat = catalogOf(ctx);
    const uri = uriParam(req) orelse
        return req.failProtocol(root.error_code.invalid_params, "Missing or non-string params.uri", "");
    const s = cat.find(uri) orelse {
        const msg = req.arena.print("No skill is served at {s}", .{uri}) catch "No skill is served at that uri";
        return req.failProtocol(root.error_code.invalid_params, msg, "");
    };
    var aw: std.Io.Writer.Allocating = .init(req.arena);
    var jw: std.json.Stringify = .{ .writer = &aw.writer };
    writeGet(&jw, req, cat.state, s) catch return false;
    req.write(aw.written());
    return true;
}

fn writeGet(jw: *std.json.Stringify, req: *const root.MethodRequest, st: *const State, s: *const Skill) std.Io.Writer.Error!void {
    try jw.beginObject();
    try jw.objectField("skill");
    try writeEntry(jw, st, s);
    try writeCache(jw, req, if (req.server) |sv| sv.read_cache else .{});
    try jw.endObject();
}

const Child = struct {
    name: []const u8,
    uri: []const u8,
    file: ?*const StoredFile,
};

fn fnv(s: []const u8) u32 {
    return std.hash.Fnv1a_32.hash(s);
}

fn handleDirRead(ctx: ?*anyopaque, req: *root.MethodRequest) bool {
    const cat = catalogOf(ctx);
    const st = cat.state;
    const uri = uriParam(req) orelse
        return req.failProtocol(root.error_code.invalid_params, "Missing or non-string params.uri", "");
    const dir = for (st.dirs) |*d| {
        if (std.mem.eql(u8, d.uri, uri)) break d;
    } else {
        const msg = req.arena.print("{s} is not a directory resource", .{uri}) catch "Not a directory resource";
        return req.failProtocol(root.error_code.invalid_params, msg, "");
    };
    var children: std.ArrayList(Child) = .empty;
    for (st.dirs) |*d| if (std.mem.eql(u8, parentOf(d.path), dir.path)) {
        children.append(req.arena, .{ .name = lastSegment(d.path), .uri = d.uri, .file = null }) catch return false;
    };
    for (st.files) |*f| if (std.mem.eql(u8, parentOf(f.path), dir.path)) {
        children.append(req.arena, .{ .name = lastSegment(f.path), .uri = f.uri, .file = f }) catch return false;
    };
    std.mem.sort(Child, children.items, {}, struct {
        fn lt(_: void, x: Child, y: Child) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);
    const scope = fnv(dir.uri);
    const start = pageStart(req, 'd', scope, children.items.len) catch
        return req.failProtocol(root.error_code.invalid_params, "Invalid cursor", "");
    const end = pageEnd(req, start, children.items.len);
    var aw: std.Io.Writer.Allocating = .init(req.arena);
    var jw: std.json.Stringify = .{ .writer = &aw.writer };
    writeDir(&jw, req, cat, dir, children.items, start, end, scope) catch return false;
    req.write(aw.written());
    return true;
}

fn writeDir(jw: *std.json.Stringify, req: *const root.MethodRequest, cat: *const Catalog, dir: *const Dir, children: []const Child, start: usize, end: usize, scope: u32) (std.Io.Writer.Error || error{OutOfMemory})!void {
    try jw.beginObject();
    try jw.objectField("resources");
    try jw.beginArray();
    for (children[start..end]) |c| {
        try jw.beginObject();
        try jw.objectField("uri");
        try jw.write(c.uri);
        // A skill's SKILL.md is named and described from its frontmatter
        // (spec "Resource Metadata"); other entries by their file name.
        const skill: ?*const Skill = if (c.file != null and std.mem.eql(u8, c.name, skill_file)) cat.find(c.uri) else null;
        try jw.objectField("name");
        try jw.write(if (skill) |s| s.name else c.name);
        if (skill) |s| {
            try jw.objectField("description");
            try jw.write(s.description);
        }
        try jw.objectField("mimeType");
        try jw.write(if (c.file) |f| f.mime_type else directory_mime_type);
        try jw.endObject();
    }
    try jw.endArray();
    if (end < children.len) {
        try jw.objectField("nextCursor");
        try jw.write(try cursor(req.arena, 'd', scope, end));
    }
    _ = dir;
    try writeCache(jw, req, if (req.server) |s| s.list_cache else .{});
    try jw.endObject();
}

fn handleRead(ctx: ?*anyopaque, req: *root.ResourceRequest) bool {
    const cat = catalogOf(ctx);
    const st = cat.state;
    if (st.by_uri.get(req.uri)) |i| {
        const f = &st.files[i];
        if (f.text) req.text(f.uri, f.mime_type, f.bytes) else req.blob(f.uri, f.mime_type, f.bytes);
        return true;
    }
    for (st.skills) |*s| {
        const d = s.dynamic orelse continue;
        if (std.mem.eql(u8, req.uri, s.uri)) {
            req.text(s.uri, "text/markdown", d.skill_md);
            return true;
        }
        const dir_uri = s.uri[0 .. s.uri.len - skill_file.len]; // keeps the trailing '/'
        if (std.mem.startsWith(u8, req.uri, dir_uri)) {
            const read = d.read orelse return false;
            return read(d.ctx, req);
        }
    }
    return false;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The files of the spec's "Example Message Flow" (their sizes and digests
/// are printed in the spec's manifest, so they double as known answers).
const spec_skill_md = "---\nname: pdf-processing\ndescription: Extract, fill, and assemble PDF documents\n---\n\n# PDF processing\n\nChoose the matching template from `templates/`.\n";
const spec_invoice = "# Invoice\n\nCustomer:\nAmount:\n";
const spec_po = "# Purchase order\n\nSupplier:\nItems:\n";
const spec_credit = "# Credit note\n\nInvoice:\nCredit amount:\n";

const meta_2026 = "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientInfo\":{\"name\":\"c\",\"version\":\"1\"},\"io.modelcontextprotocol/clientCapabilities\":{}}";

fn call(s: *root.Server, out: *std.Io.Writer.Allocating, line: []const u8) ![]const u8 {
    out.clearRetainingCapacity();
    try s.handleMessage(line, &out.writer);
    return out.written();
}

fn parsed(a: std.mem.Allocator, line: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, a, std.mem.trimEnd(u8, line, "\n"), .{});
}

test "spec example: digests and sizes of the example files are the published ones" {
    var cat = try Catalog.load(testing.allocator, &.{
        .{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md },
        .{ .path = "pdf-processing/templates/invoice.md", .bytes = spec_invoice },
        .{ .path = "pdf-processing/templates/purchase-order.md", .bytes = spec_po },
    }, &.{}, .{});
    defer cat.deinit();
    try testing.expectEqual(@as(usize, 1), cat.skills().len);
    const s = cat.skills()[0];
    try testing.expectEqualStrings("skill://pdf-processing/SKILL.md", s.uri);
    const want = [_]struct { []const u8, []const u8, usize }{
        .{ "skill://pdf-processing/SKILL.md", "sha256:99b737495721155ece826d57521e2d66141ebdc1344a400487481ea2642ab19e", 151 },
        .{ "skill://pdf-processing/templates/invoice.md", "sha256:61f4ea6d2c75fde1b4977219e7e3107d491c3c26aefb6686e84d6281c088d9ee", 29 },
        .{ "skill://pdf-processing/templates/purchase-order.md", "sha256:f2ff774b1737ff3dec81c47946f9976f18a1a9f69dda0a81f22eabd95173c158", 35 },
    };
    try testing.expectEqual(want.len, s.files.?.len);
    for (want, s.files.?) |w, m| {
        const f = cat.state.files[m];
        try testing.expectEqualStrings(w[0], f.uri);
        try testing.expectEqualStrings(w[1], &f.digest);
        try testing.expectEqual(w[2], f.bytes.len);
    }
    // The credit note the spec adds later.
    var cat2 = try Catalog.load(testing.allocator, &.{
        .{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md },
        .{ .path = "pdf-processing/templates/credit-note.md", .bytes = spec_credit },
    }, &.{}, .{});
    defer cat2.deinit();
    const f = cat2.state.files[cat2.skills()[0].files.?[1]]; // sorted: SKILL.md, then templates/
    try testing.expectEqualStrings("sha256:766bffa8d4908ce897e1727ca22e4bf0fa796620b35218ce2132a124545626f1", &f.digest);
    try testing.expectEqual(@as(usize, 39), f.bytes.len);
}

test "spec example flow over the wire: discover, skills/list, resources/read, directory read, skills/get" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    var cat = try Catalog.load(testing.allocator, &.{
        .{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md },
        .{ .path = "pdf-processing/templates/invoice.md", .bytes = spec_invoice },
        .{ .path = "pdf-processing/templates/purchase-order.md", .bytes = spec_po },
    }, &.{}, .{});
    defer cat.deinit();
    var s = root.Server.init(testing.allocator, .{ .name = "docs-server", .version = "1" });
    defer s.deinit();
    s.list_cache = .{ .ttl_ms = 300000, .scope = .public };
    s.read_cache = .{ .ttl_ms = 300000, .scope = .public };
    try cat.attach(&s);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    const disc = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{" ++ meta_2026 ++ "}}"));
    const caps = disc.object.get("result").?.object.get("capabilities").?.object;
    try testing.expect(caps.get("resources") != null);
    try testing.expect(caps.get("extensions").?.object.get(extension_id).?.object.get("directoryRead").?.bool);

    // skills/list: the spec's result, value for value.
    const list = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"skills/list\",\"params\":{" ++ meta_2026 ++ "}}"));
    const want_list = try parsed(a,
        \\{"resultType":"complete","skills":[{"uri":"skill://pdf-processing/SKILL.md","frontmatter":{"name":"pdf-processing","description":"Extract, fill, and assemble PDF documents"},"resources":[{"uri":"skill://pdf-processing/SKILL.md","digest":"sha256:99b737495721155ece826d57521e2d66141ebdc1344a400487481ea2642ab19e","size":151},{"uri":"skill://pdf-processing/templates/invoice.md","digest":"sha256:61f4ea6d2c75fde1b4977219e7e3107d491c3c26aefb6686e84d6281c088d9ee","size":29},{"uri":"skill://pdf-processing/templates/purchase-order.md","digest":"sha256:f2ff774b1737ff3dec81c47946f9976f18a1a9f69dda0a81f22eabd95173c158","size":35}]}],"ttlMs":300000,"cacheScope":"public"}
    );
    try expectSubset(want_list, list.object.get("result").?);

    // resources/read of SKILL.md: the spec's contents.
    const read = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://pdf-processing/SKILL.md\"}}"));
    const want_read = try parsed(a,
        \\{"resultType":"complete","contents":[{"uri":"skill://pdf-processing/SKILL.md","mimeType":"text/markdown","text":"---\nname: pdf-processing\ndescription: Extract, fill, and assemble PDF documents\n---\n\n# PDF processing\n\nChoose the matching template from `templates/`.\n"}],"ttlMs":300000,"cacheScope":"public"}
    );
    try expectSubset(want_read, read.object.get("result").?);

    // resources/directory/read of templates/.
    const dir = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/directory/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://pdf-processing/templates\"}}"));
    const want_dir = try parsed(a,
        \\{"resultType":"complete","resources":[{"uri":"skill://pdf-processing/templates/invoice.md","name":"invoice.md","mimeType":"text/markdown"},{"uri":"skill://pdf-processing/templates/purchase-order.md","name":"purchase-order.md","mimeType":"text/markdown"}],"ttlMs":300000,"cacheScope":"public"}
    );
    try expectSubset(want_dir, dir.object.get("result").?);

    // The skill root lists SKILL.md under the skill's name, and templates/ as a directory.
    const rootdir = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"resources/directory/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://pdf-processing\"}}"));
    const want_root = try parsed(a,
        \\{"resources":[{"uri":"skill://pdf-processing/SKILL.md","name":"pdf-processing","description":"Extract, fill, and assemble PDF documents","mimeType":"text/markdown"},{"uri":"skill://pdf-processing/templates","name":"templates","mimeType":"inode/directory"}]}
    );
    try expectSubset(want_root, rootdir.object.get("result").?);

    // skills/get.
    const get = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"skills/get\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://pdf-processing/SKILL.md\"}}"));
    try testing.expectEqualStrings("complete", get.object.get("result").?.object.get("resultType").?.string);
    try expectSubset(want_list.object.get("skills").?.array.items[0], get.object.get("result").?.object.get("skill").?);
    try testing.expectEqual(@as(i64, 300000), get.object.get("result").?.object.get("ttlMs").?.integer);
}

/// Every key of `want` is in `got` with an equal value (recursively for
/// objects; arrays compare element by element and must have the same length).
fn expectSubset(want: std.json.Value, got: std.json.Value) !void {
    switch (want) {
        .object => |o| {
            if (got != .object) return error.TestExpectedObject;
            var it = o.iterator();
            while (it.next()) |e| {
                const g = got.object.get(e.key_ptr.*) orelse {
                    std.debug.print("missing key {s}\n", .{e.key_ptr.*});
                    return error.TestMissingKey;
                };
                try expectSubset(e.value_ptr.*, g);
            }
        },
        .array => |arr| {
            if (got != .array) return error.TestExpectedArray;
            try testing.expectEqual(arr.items.len, got.array.items.len);
            for (arr.items, got.array.items) |w, g| try expectSubset(w, g);
        },
        .string => |s| try testing.expectEqualStrings(s, got.string),
        .integer => |i| try testing.expectEqual(i, got.integer),
        .bool => |b| try testing.expectEqual(b, got.bool),
        .null => try testing.expect(got == .null),
        .float => |f| try testing.expectEqual(f, got.float),
        .number_string => |s| try testing.expectEqualStrings(s, got.number_string),
    }
}

test "errors: unknown skill, not a directory, unknown file, missing uri (spec Error Handling)" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    var cat = try Catalog.load(testing.allocator, &.{.{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md }}, &.{}, .{});
    defer cat.deinit();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try cat.attach(&s);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"skills/get\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://acme/billing/chargebacks/SKILL.md\"}}", "No skill is served at skill://acme/billing/chargebacks/SKILL.md" },
        .{ "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"resources/directory/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://pdf-processing/SKILL.md\"}}", "skill://pdf-processing/SKILL.md is not a directory resource" },
        .{ "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"skills/get\",\"params\":{" ++ meta_2026 ++ "}}", "Missing or non-string params.uri" },
        .{ "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"resources/directory/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":7}}", "Missing or non-string params.uri" },
    };
    for (cases) |c| {
        const v = try parsed(a, try call(&s, &out, c[0]));
        const err = v.object.get("error").?.object;
        try testing.expectEqual(@as(i64, -32602), err.get("code").?.integer);
        try testing.expectEqualStrings(c[1], err.get("message").?.string);
    }
    // An unknown skill file is the base protocol's not-found (-32602 on 2026-07-28).
    const v = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"resources/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://pdf-processing/nope.md\"}}"));
    try testing.expectEqual(@as(i64, -32602), v.object.get("error").?.object.get("code").?.integer);
}

test "session era: the methods work after initialize, without caching fields" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    var cat = try Catalog.load(testing.allocator, &.{.{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md }}, &.{}, .{ .directory_read = false });
    defer cat.deinit();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.setCapabilityExtras("{\"io.modelcontextprotocol/ui\":{}}", "");
    try cat.attach(&s);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const init = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"c\",\"version\":\"1\"}}}"));
    const ext = init.object.get("result").?.object.get("capabilities").?.object.get("extensions").?.object;
    try testing.expect(ext.get("io.modelcontextprotocol/ui") != null); // the existing extension is kept
    try testing.expectEqual(@as(usize, 0), ext.get(extension_id).?.object.count()); // no directoryRead
    const list = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"skills/list\"}"));
    const r = list.object.get("result").?.object;
    try testing.expect(r.get("ttlMs") == null and r.get("cacheScope") == null and r.get("resultType") == null);
    try testing.expectEqual(@as(usize, 1), r.get("skills").?.array.items.len);
    // Without directoryRead the method is not served.
    const dr = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/directory/read\",\"params\":{\"uri\":\"skill://pdf-processing\"}}"));
    try testing.expectEqual(@as(i64, -32601), dr.object.get("error").?.object.get("code").?.integer);
    // A second attach, or a server already declaring the extension, is refused.
    try testing.expectError(error.AlreadyAttached, cat.attach(&s));
    var cat2 = try Catalog.load(testing.allocator, &.{}, &.{}, .{});
    defer cat2.deinit();
    try testing.expectError(error.AlreadyAttached, cat2.attach(&s));
}

fn otherMethod(_: ?*anyopaque, req: *root.MethodRequest) bool {
    req.write("{}");
    return true;
}

test "attach is all or nothing: a clash leaves the server as it was (review RV-1)" {
    var cat = try Catalog.load(testing.allocator, &.{.{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md }}, &.{}, .{});
    defer cat.deinit();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try s.addMethod(.{ .name = "resources/directory/read", .handler = otherMethod });
    try testing.expectError(error.DuplicateMethod, cat.attach(&s));
    try testing.expectEqual(@as(usize, 1), s.custom_methods.items.len);
    try testing.expectEqual(@as(usize, 0), s.resource_templates.items.len);
    try testing.expectEqualStrings("", s.extensions_json);
    try testing.expect(!cat.attached);
    var s2 = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s2.deinit();
    try s2.addResourceTemplate(.{ .uri_template = uri_template, .name = "mine" });
    try testing.expectError(error.DuplicateResourceTemplate, cat.attach(&s2));
    try testing.expectEqual(@as(usize, 0), s2.custom_methods.items.len);
    // OOM at every allocation of attach also leaves the server untouched.
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var fa = testing.FailingAllocator.init(testing.allocator, .{});
        var s3 = root.Server.init(fa.allocator(), .{ .name = "t", .version = "0" });
        defer s3.deinit();
        var c3 = try Catalog.load(fa.allocator(), &.{.{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md }}, &.{}, .{});
        defer c3.deinit();
        fa.fail_index = fa.alloc_index + fail_index; // fail inside attach only
        if (c3.attach(&s3)) |_| break else |e| {
            try testing.expectEqual(error.OutOfMemory, e);
            try testing.expectEqual(@as(usize, 0), s3.custom_methods.items.len);
            try testing.expectEqual(@as(usize, 0), s3.resource_templates.items.len);
            try testing.expectEqualStrings("", s3.extensions_json);
        }
    }
    try testing.expect(fail_index > 2);
}

test "frontmatter: billion laughs and alias chains are refused at load (review RV-2, RV-3)" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    // Nine levels of ten-fold aliases: about 10^9 JSON values from ~30 lines.
    var lol: std.ArrayList(u8) = .empty;
    try lol.appendSlice(a, "---\nname: x\ndescription: d\nl0: &l0 [lol]\n");
    for (1..10) |i| {
        try lol.print(a, "l{d}: &l{d} [", .{ i, i });
        for (0..10) |j| try lol.print(a, "{s}*l{d}", .{ if (j == 0) "" else ", ", i - 1 });
        try lol.appendSlice(a, "]\n");
    }
    try lol.appendSlice(a, "---\n");
    // An alias chain that nests deeper than the depth cap once expanded.
    var chain: std.ArrayList(u8) = .empty;
    try chain.appendSlice(a, "---\nname: x\ndescription: d\nc0: &c0 [1]\n");
    for (1..200) |i| try chain.print(a, "c{d}: &c{d} [*c{d}]\n", .{ i, i, i - 1 });
    try chain.appendSlice(a, "---\n");
    for ([_][]const u8{ lol.items, chain.items }) |md| {
        var c = try Catalog.load(testing.allocator, &.{.{ .path = "x/SKILL.md", .bytes = md }}, &.{}, .{});
        defer c.deinit();
        try testing.expectEqual(@as(usize, 0), c.skills().len);
        try testing.expectEqual(Problem.frontmatter_too_large, c.skipped()[0].problem);
    }
    // Ordinary aliases still expand.
    var ok = try Catalog.load(testing.allocator, &.{.{ .path = "x/SKILL.md", .bytes = "---\nname: x\ndescription: &d desc\nalso: *d\n---\n" }}, &.{}, .{});
    defer ok.deinit();
    try testing.expect(std.mem.find(u8, ok.skills()[0].frontmatter_json, "\"also\":\"desc\"") != null);
}

test "paths: a file that is also a directory, non-UTF-8 bytes, and a reg-name authority (review RV-5, RV-6, RV-8)" {
    const md = "---\nname: x\ndescription: d\n---\n";
    try testing.expectError(error.PathConflict, Catalog.load(testing.allocator, &.{ .{ .path = "a/x/SKILL.md", .bytes = md }, .{ .path = "a/x", .bytes = "" } }, &.{}, .{}));
    try testing.expectError(error.BadPath, Catalog.load(testing.allocator, &.{.{ .path = "a\xff/x/SKILL.md", .bytes = md }}, &.{}, .{}));
    var c = try Catalog.load(testing.allocator, &.{.{ .path = "u:p@h/x/SKILL.md", .bytes = md }}, &.{}, .{});
    defer c.deinit();
    try testing.expectEqualStrings("skill://u%3Ap%40h/x/SKILL.md", c.skills()[0].uri);
    var c2 = try Catalog.load(testing.allocator, &.{.{ .path = "a/x:y@z/x/SKILL.md", .bytes = md }}, &.{}, .{});
    defer c2.deinit();
    try testing.expectEqualStrings("skill://a/x:y@z/x/SKILL.md", c2.skills()[0].uri); // later segments keep them
}

test "frontmatter: verbatim JSON of every field, nested values, and the format rules" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const md = "---\r\nname: refunds\r\ndescription: Process refunds\r\nlicense: Apache-2.0\r\nmetadata:\r\n  author: acme\r\n  version: \"1.0\"\r\nallowed-tools: Bash(git:*) Read\r\nn: 3\r\nf: 1.5\r\nflag: true\r\nnothing:\r\nlist: [a, 2]\r\n---\r\nbody\r\n";
    var cat = try Catalog.load(testing.allocator, &.{
        .{ .path = "acme/billing/refunds/SKILL.md", .bytes = md },
        .{ .path = "bom/SKILL.md", .bytes = "\xEF\xBB\xBF---\nname: bom\ndescription: d\n---\n" },
    }, &.{}, .{});
    defer cat.deinit();
    try testing.expectEqual(@as(usize, 2), cat.skills().len);
    const s = cat.skills()[0];
    try testing.expectEqualStrings("refunds", s.name);
    try testing.expectEqualStrings("skill://acme/billing/refunds/SKILL.md", s.uri);
    const got = try std.json.parseFromSliceLeaky(std.json.Value, a, s.frontmatter_json, .{});
    const want = try std.json.parseFromSliceLeaky(std.json.Value, a,
        \\{"name":"refunds","description":"Process refunds","license":"Apache-2.0","metadata":{"author":"acme","version":"1.0"},"allowed-tools":"Bash(git:*) Read","n":3,"f":1.5,"flag":true,"nothing":null,"list":["a",2]}
    , .{});
    try expectSubset(want, got);
    try testing.expectEqual(want.object.count(), got.object.count());

    const bad = [_]struct { []const u8, []const u8, Problem }{
        .{ "a/x", "no frontmatter\n", .no_frontmatter },
        .{ "a/x", "---\nname: x\ndescription: d\n", .no_frontmatter }, // never closed
        .{ "a/x", "---\nname: [x\n---\n", .bad_yaml },
        .{ "a/x", "---\n- x\n---\n", .frontmatter_not_mapping },
        .{ "a/x", "---\n---\n", .frontmatter_not_mapping },
        .{ "a/x", "---\nname: x\ndescription: d\n[1]: k\n---\n", .unrepresentable_value },
        .{ "a/x", "---\nname: x\ndescription: d\nv: .inf\n---\n", .unrepresentable_value },
        .{ "a/x", "---\ndescription: d\n---\n", .missing_name },
        .{ "a/x", "---\nname: 7\ndescription: d\n---\n", .missing_name },
        .{ "a/X", "---\nname: X\ndescription: d\n---\n", .bad_name },
        .{ "a/-x", "---\nname: -x\ndescription: d\n---\n", .bad_name },
        .{ "a/x-", "---\nname: x-\ndescription: d\n---\n", .bad_name },
        .{ "a/a--b", "---\nname: a--b\ndescription: d\n---\n", .bad_name },
        .{ "a/y", "---\nname: x\ndescription: d\n---\n", .name_mismatch },
        .{ "a/x", "---\nname: x\n---\n", .missing_description },
        .{ "a/x", "---\nname: x\ndescription: \"\"\n---\n", .bad_description },
        .{ "a/x", "---\nname: x\ndescription: d\nname: y\n---\n", .bad_yaml }, // duplicate key
    };
    for (bad) |b| {
        const path = try std.mem.concat(a, u8, &.{ b[0], "/SKILL.md" });
        var c = try Catalog.load(testing.allocator, &.{.{ .path = path, .bytes = b[1] }}, &.{}, .{});
        defer c.deinit();
        try testing.expectEqual(@as(usize, 0), c.skills().len);
        try testing.expectEqual(@as(usize, 1), c.skipped().len);
        testing.expectEqual(b[2], c.skipped()[0].problem) catch |e| {
            std.debug.print("case {s}: {s}\n", .{ b[0], b[1] });
            return e;
        };
        // strict refuses, and names the skill.
        var diag: Diagnostic = .{};
        try testing.expectError(error.InvalidSkill, Catalog.load(testing.allocator, &.{.{ .path = path, .bytes = b[1] }}, &.{}, .{ .strict = true, .diagnostic = &diag }));
        try testing.expectEqualStrings(b[0], diag.path());
        try testing.expectEqual(b[2], diag.problem);
    }
    // Name and description limits at the edge (characters, not bytes).
    const n64: [64]u8 = @splat('a');
    const n65: [65]u8 = @splat('a');
    const d1024 = try a.alloc(u8, 1024 * 2);
    for (0..1024) |i| @memcpy(d1024[i * 2 ..][0..2], "č");
    const d1025 = try std.mem.concat(a, u8, &.{ d1024, "x" });
    const edge = [_]struct { []const u8, []const u8, bool }{
        .{ &n64, "d", true },
        .{ &n65, "d", false },
        .{ "x", d1024, true },
        .{ "x", d1025, false },
    };
    for (edge) |e| {
        const md2 = try std.mem.concat(a, u8, &.{ "---\nname: ", e[0], "\ndescription: ", e[1], "\n---\n" });
        const path = try std.mem.concat(a, u8, &.{ e[0], "/SKILL.md" });
        var c = try Catalog.load(testing.allocator, &.{.{ .path = path, .bytes = md2 }}, &.{}, .{});
        defer c.deinit();
        try testing.expectEqual(@as(usize, @intFromBool(e[2])), c.skills().len);
    }
}

test "nested skills: the enclosing manifest lists the nested files, the listing stays flat" {
    var cat = try Catalog.load(testing.allocator, &.{
        .{ .path = "outer/SKILL.md", .bytes = "---\nname: outer\ndescription: o\n---\n" },
        .{ .path = "outer/inner/SKILL.md", .bytes = "---\nname: inner\ndescription: i\n---\n" },
        .{ .path = "outer/inner/ref.md", .bytes = "r" },
        .{ .path = "outer/broken/SKILL.md", .bytes = "no frontmatter" },
        .{ .path = "stray/readme.md", .bytes = "not in any skill" },
    }, &.{}, .{});
    defer cat.deinit();
    try testing.expectEqual(@as(usize, 2), cat.skills().len);
    try testing.expectEqualStrings("outer", cat.skills()[0].path);
    try testing.expectEqualStrings("outer/inner", cat.skills()[1].path);
    try testing.expectEqual(@as(usize, 4), cat.skills()[0].files.?.len); // its own + inner's 2 + broken's SKILL.md
    try testing.expectEqual(@as(usize, 2), cat.skills()[1].files.?.len);
    try testing.expectEqual(@as(usize, 1), cat.skipped().len);
    // A file in no served skill is not served at all.
    try testing.expect(cat.state.by_uri.get("skill://stray/readme.md") == null);
    try testing.expect(cat.state.by_uri.get("skill://outer/broken/SKILL.md") != null);
}

test "limits: 512 files and 16 MiB per skill are served, one more is not" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const md = "---\nname: big\ndescription: d\n---\n";
    for ([_]usize{ 512, 513 }) |n| {
        const files = try a.alloc(File, n);
        files[0] = .{ .path = "big/SKILL.md", .bytes = md };
        for (files[1..], 1..) |*f, i| f.* = .{ .path = try a.print("big/f{d}", .{i}), .bytes = "" };
        var c = try Catalog.load(testing.allocator, files, &.{}, .{});
        defer c.deinit();
        try testing.expectEqual(n == 512, c.skills().len == 1);
        if (n == 513) try testing.expectEqual(Problem.too_many_files, c.skipped()[0].problem);
    }
    const blob = try a.alloc(u8, max_skill_bytes - md.len);
    @memset(blob, 0);
    for ([_]usize{ 0, 1 }) |extra| {
        const more = try a.alloc(u8, extra);
        @memset(more, 0);
        var c = try Catalog.load(testing.allocator, &.{
            .{ .path = "big/SKILL.md", .bytes = md },
            .{ .path = "big/blob.bin", .bytes = blob },
            .{ .path = "big/more.bin", .bytes = more },
        }, &.{}, .{});
        defer c.deinit();
        try testing.expectEqual(extra == 0, c.skills().len == 1);
        if (extra == 1) try testing.expectEqual(Problem.too_large, c.skipped()[0].problem);
    }
}

test "files: binary bytes are a base64 blob, UTF-8 is text; uri bytes outside the reserved set are percent-encoded" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    var cat = try Catalog.load(testing.allocator, &.{
        .{ .path = "x/SKILL.md", .bytes = "---\nname: x\ndescription: d\n---\n" },
        .{ .path = "x/img.png", .bytes = "\x89PNG\xff" },
        .{ .path = "x/a b#c?.txt", .bytes = "hi" },
        .{ .path = "x/data", .bytes = "plain", .mime_type = "application/x-custom" },
    }, &.{}, .{});
    defer cat.deinit();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try cat.attach(&s);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const png = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://x/img.png\"}}"));
    const c0 = png.object.get("result").?.object.get("contents").?.array.items[0].object;
    var raw: [5]u8 = undefined;
    try std.base64.standard.Decoder.decode(&raw, c0.get("blob").?.string);
    try testing.expectEqualStrings("\x89PNG\xff", &raw);
    try testing.expectEqualStrings("image/png", c0.get("mimeType").?.string);
    try testing.expect(c0.get("text") == null);
    const sp = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://x/a%20b%23c%3F.txt\"}}"));
    const c1 = sp.object.get("result").?.object.get("contents").?.array.items[0].object;
    try testing.expectEqualStrings("hi", c1.get("text").?.string);
    try testing.expectEqualStrings("text/plain", c1.get("mimeType").?.string);
    const cu = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/read\",\"params\":{" ++ meta_2026 ++ ",\"uri\":\"skill://x/data\"}}"));
    try testing.expectEqualStrings("application/x-custom", cu.object.get("result").?.object.get("contents").?.array.items[0].object.get("mimeType").?.string);
    // The template is advertised.
    const tl = try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/templates/list\",\"params\":{" ++ meta_2026 ++ "}}");
    try testing.expect(std.mem.find(u8, tl, "\"uriTemplate\":\"skill://{+path}\"") != null);
}

test "pagination: skills/list and directory reads page with opaque cursors bound to their listing" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    var files: std.ArrayList(File) = .empty;
    for (0..5) |i| {
        const name = try a.print("s{d}", .{i});
        try files.append(a, .{ .path = try a.print("{s}/SKILL.md", .{name}), .bytes = try a.print("---\nname: {s}\ndescription: d\n---\n", .{name}) });
    }
    var cat = try Catalog.load(testing.allocator, files.items, &.{}, .{});
    defer cat.deinit();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    s.page_size = 2;
    try cat.attach(&s);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var seen: usize = 0;
    var cur: ?[]const u8 = null;
    var pages: usize = 0;
    while (true) {
        const line = if (cur) |c|
            try a.print("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"skills/list\",\"params\":{{\"cursor\":\"{s}\"}}}}", .{c})
        else
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"skills/list\"}";
        const v = try parsed(a, try call(&s, &out, line));
        const r = v.object.get("result").?.object;
        seen += r.get("skills").?.array.items.len;
        pages += 1;
        const nc = r.get("nextCursor") orelse break;
        cur = try a.dupe(u8, nc.string);
    }
    try testing.expectEqual(@as(usize, 5), seen);
    try testing.expectEqual(@as(usize, 3), pages);
    // A forged cursor, a cursor of another listing and a non-string one are -32602.
    const skills_cursor = try cursor(a, 's', 0, 2);
    const dir_cursor = try cursor(a, 'd', fnv("skill://s0"), 0);
    for ([_][]const u8{
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"skills/list\",\"params\":{\"cursor\":\"zzz\"}}",
        try a.print("{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"skills/list\",\"params\":{{\"cursor\":\"{s}\"}}}}", .{dir_cursor}),
        try a.print("{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/directory/read\",\"params\":{{\"uri\":\"skill://s0\",\"cursor\":\"{s}\"}}}}", .{skills_cursor}),
        try a.print("{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"skills/list\",\"params\":{{\"cursor\":\"{s}\"}}}}", .{try cursor(a, 's', 0, 6)}),
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"skills/list\",\"params\":{\"cursor\":5}}",
    }) |line| {
        const v = try parsed(a, try call(&s, &out, line));
        try testing.expectEqual(@as(i64, -32602), v.object.get("error").?.object.get("code").?.integer);
    }
    // A directory's own cursor works.
    const ok = try parsed(a, try call(&s, &out, try a.print("{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/directory/read\",\"params\":{{\"uri\":\"skill://s0\",\"cursor\":\"{s}\"}}}}", .{dir_cursor})));
    try testing.expect(ok.object.get("result") != null);
}

fn readGenerated(_: ?*anyopaque, req: *root.ResourceRequest) bool {
    if (!std.mem.eql(u8, req.uri, "skill://reports/daily/today.md")) return false;
    req.text(req.uri, "text/markdown", "# today\n");
    return true;
}

test "dynamic skills: \"resources\":\"dynamic\", SKILL.md served, other reads delegated, overlaps refused" {
    var st: std.heap.ArenaAllocator = .init(testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const dyn = [_]Dynamic{.{ .path = "reports/daily", .skill_md = "---\nname: daily\ndescription: Today's report\n---\n", .read = readGenerated }};
    var cat = try Catalog.load(testing.allocator, &.{.{ .path = "pdf-processing/SKILL.md", .bytes = spec_skill_md }}, &dyn, .{});
    defer cat.deinit();
    var s = root.Server.init(testing.allocator, .{ .name = "t", .version = "0" });
    defer s.deinit();
    try cat.attach(&s);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const get = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"skills/get\",\"params\":{\"uri\":\"skill://reports/daily/SKILL.md\"}}"));
    const sk = get.object.get("result").?.object.get("skill").?.object;
    try testing.expectEqualStrings("dynamic", sk.get("resources").?.string);
    try testing.expectEqualStrings("daily", sk.get("frontmatter").?.object.get("name").?.string);
    const md = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"resources/read\",\"params\":{\"uri\":\"skill://reports/daily/SKILL.md\"}}"));
    try testing.expect(std.mem.startsWith(u8, md.object.get("result").?.object.get("contents").?.array.items[0].object.get("text").?.string, "---\nname: daily"));
    const gen = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/read\",\"params\":{\"uri\":\"skill://reports/daily/today.md\"}}"));
    try testing.expectEqualStrings("# today\n", gen.object.get("result").?.object.get("contents").?.array.items[0].object.get("text").?.string);
    const miss = try parsed(a, try call(&s, &out, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/read\",\"params\":{\"uri\":\"skill://reports/daily/other.md\"}}"));
    try testing.expect(miss.object.get("error") != null);
    // Overlaps.
    const md_x = "---\nname: x\ndescription: d\n---\n";
    try testing.expectError(error.OverlappingDynamicSkill, Catalog.load(testing.allocator, &.{.{ .path = "x/a.md", .bytes = "" }}, &.{.{ .path = "x", .skill_md = md_x }}, .{}));
    try testing.expectError(error.OverlappingDynamicSkill, Catalog.load(testing.allocator, &.{.{ .path = "x/SKILL.md", .bytes = md_x }}, &.{.{ .path = "x/sub/x", .skill_md = md_x }}, .{}));
    try testing.expectError(error.OverlappingDynamicSkill, Catalog.load(testing.allocator, &.{}, &.{ .{ .path = "x", .skill_md = md_x }, .{ .path = "x/y/x", .skill_md = md_x } }, .{}));
}

test "paths: duplicates, empty and dot segments are refused; reload swaps contents" {
    const md = "---\nname: x\ndescription: d\n---\n";
    try testing.expectError(error.DuplicatePath, Catalog.load(testing.allocator, &.{ .{ .path = "x/SKILL.md", .bytes = md }, .{ .path = "x/SKILL.md", .bytes = md } }, &.{}, .{}));
    for ([_][]const u8{ "", "/x/SKILL.md", "x//SKILL.md", "x/../SKILL.md", "x/./a", "x/" }) |p| {
        try testing.expectError(error.BadPath, Catalog.load(testing.allocator, &.{.{ .path = p, .bytes = md }}, &.{}, .{}));
    }
    var c = try Catalog.load(testing.allocator, &.{.{ .path = "SKILL.md", .bytes = md }}, &.{}, .{});
    defer c.deinit();
    try testing.expectEqual(Problem.no_directory, c.skipped()[0].problem);
    try c.reload(&.{.{ .path = "x/SKILL.md", .bytes = md }}, &.{});
    try testing.expectEqual(@as(usize, 1), c.skills().len);
    try testing.expectEqual(@as(usize, 0), c.skipped().len);
    // A failed reload keeps the old contents.
    try testing.expectError(error.BadPath, c.reload(&.{.{ .path = "..", .bytes = md }}, &.{}));
    try testing.expectEqual(@as(usize, 1), c.skills().len);
}

test "loadDir: reads a tree, skips dot entries and symlinks" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.createDirPath(io, "git-workflow/scripts");
    try tmp.dir.createDirPath(io, ".hidden");
    try tmp.dir.writeFile(io, .{ .sub_path = "git-workflow/SKILL.md", .data = "---\nname: git-workflow\ndescription: Git conventions\n---\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "git-workflow/scripts/run.sh", .data = "echo hi\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "git-workflow/.DS_Store", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".hidden/SKILL.md", .data = "---\nname: hidden\ndescription: d\n---\n" });
    tmp.dir.symLink(io, "scripts/run.sh", "git-workflow/link.sh", .{}) catch {};
    var cat = try Catalog.loadDir(testing.allocator, io, tmp.dir, &.{}, .{});
    defer cat.deinit();
    try testing.expectEqual(@as(usize, 1), cat.skills().len);
    const s = cat.skills()[0];
    try testing.expectEqualStrings("git-workflow", s.name);
    try testing.expectEqual(@as(usize, 2), s.files.?.len);
    try testing.expectEqualStrings("skill://git-workflow/scripts/run.sh", cat.state.files[s.files.?[1]].uri);
    try testing.expectEqualStrings("text/x-shellscript", cat.state.files[s.files.?[1]].mime_type);
}

test "mimeTypeFor: by extension, case-insensitive, text/binary fallback" {
    try testing.expectEqualStrings("text/markdown", mimeTypeFor("a/SKILL.md", true));
    try testing.expectEqualStrings("image/png", mimeTypeFor("a/X.PNG", false));
    try testing.expectEqualStrings("text/plain", mimeTypeFor("a/LICENSE", true));
    try testing.expectEqualStrings("application/octet-stream", mimeTypeFor("a/blob", false));
    try testing.expectEqualStrings("application/octet-stream", mimeTypeFor("a/x.unknown", false));
    try testing.expectEqualStrings("text/plain", mimeTypeFor("a.d/noext", true));
}
