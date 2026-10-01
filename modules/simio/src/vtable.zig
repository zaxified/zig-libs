// SPDX-License-Identifier: MIT

//! The `std.Io.VTable` every simulated host shares. It starts as a copy of
//! `std.Io.failing` — so an operation simio does not simulate yet returns the
//! error `failing` returns (never a fabricated success) — and overrides what
//! is simulated. `Io.userdata` is the `*Host` that issued the call.

const std = @import("std");
const sched = @import("sched.zig");

const Io = std.Io;
const net = Io.net;
const Dir = Io.Dir;
const File = Io.File;
const Alignment = std.mem.Alignment;
const Host = sched.Host;
const Sim = sched.Sim;

pub const vtable: Io.VTable = blk: {
    var vt = Io.failing.vtable.*;
    vt.crashHandler = crashHandler;
    vt.async = async;
    vt.concurrent = concurrent;
    vt.await = await;
    vt.cancel = cancel;
    vt.groupAsync = groupAsync;
    vt.groupConcurrent = groupConcurrent;
    vt.groupAwait = groupAwait;
    vt.groupCancel = groupCancel;
    vt.recancel = recancel;
    vt.swapCancelProtection = swapCancelProtection;
    vt.checkCancel = checkCancel;
    vt.futexWait = futexWait;
    vt.futexWaitUncancelable = futexWaitUncancelable;
    vt.futexWake = futexWake;
    vt.now = now;
    vt.clockResolution = clockResolution;
    vt.sleep = sleep;
    vt.random = random;
    vt.randomSecure = randomSecure;
    vt.operate = operate;
    vt.batchAwaitAsync = batchAwaitAsync;
    vt.batchAwaitConcurrent = batchAwaitConcurrent;
    vt.batchCancel = batchCancel;
    vt.netListenIp = netListenIp;
    vt.netAccept = netAccept;
    vt.netBindIp = netBindIp;
    vt.netConnectIp = netConnectIp;
    vt.netSend = netSend;
    vt.netRead = netRead;
    vt.netWrite = netWrite;
    vt.netClose = netClose;
    vt.netShutdown = netShutdown;
    vt.netLookup = netLookup;
    vt.fileMemoryMapCreate = fileMemoryMapCreate;
    vt.fileMemoryMapDestroy = fileMemoryMapDestroy;
    vt.fileMemoryMapSetLength = fileMemoryMapSetLength;
    vt.fileMemoryMapRead = fileMemoryMapRead;
    vt.fileMemoryMapWrite = fileMemoryMapWrite;
    vt.dirSymLink = dirSymLink;
    vt.dirReadLink = dirReadLink;
    vt.dirHardLink = dirHardLink;
    vt.fileHardLink = fileHardLink;
    vt.fileRealPath = fileRealPath;
    vt.dirSetPermissions = dirSetPermissions;
    vt.dirSetFilePermissions = dirSetFilePermissions;
    vt.fileSetPermissions = fileSetPermissions;
    vt.dirSetOwner = dirSetOwner;
    vt.dirSetFileOwner = dirSetFileOwner;
    vt.fileSetOwner = fileSetOwner;
    vt.dirSetTimestamps = dirSetTimestamps;
    vt.fileSetTimestamps = fileSetTimestamps;
    vt.netListenUnix = netListenUnix;
    vt.netConnectUnix = netConnectUnix;
    vt.dirCreateDir = dirCreateDir;
    vt.dirCreateDirPath = dirCreateDirPath;
    vt.dirCreateDirPathOpen = dirCreateDirPathOpen;
    vt.dirOpenDir = dirOpenDir;
    vt.dirStat = dirStat;
    vt.dirStatFile = dirStatFile;
    vt.dirAccess = dirAccess;
    vt.dirCreateFile = dirCreateFile;
    vt.dirCreateFileAtomic = dirCreateFileAtomic;
    vt.dirOpenFile = dirOpenFile;
    vt.dirClose = dirClose;
    vt.dirRead = dirRead;
    vt.dirRealPath = dirRealPath;
    vt.dirRealPathFile = dirRealPathFile;
    vt.dirDeleteFile = dirDeleteFile;
    vt.dirDeleteDir = dirDeleteDir;
    vt.dirRename = dirRename;
    vt.dirRenamePreserve = dirRenamePreserve;
    vt.fileStat = fileStat;
    vt.fileLength = fileLength;
    vt.fileClose = fileClose;
    vt.fileWritePositional = fileWritePositional;
    vt.fileReadPositional = fileReadPositional;
    vt.fileSeekBy = fileSeekBy;
    vt.fileSeekTo = fileSeekTo;
    vt.fileSync = fileSync;
    vt.fileIsTty = fileIsTty;
    vt.fileSupportsAnsiEscapeCodes = fileIsTty;
    vt.fileSetLength = fileSetLength;
    vt.fileLock = fileLock;
    vt.fileTryLock = fileTryLock;
    vt.fileUnlock = fileUnlock;
    vt.fileDowngradeLock = fileDowngradeLock;
    break :blk vt;
};

fn hostOf(userdata: ?*anyopaque) *Host {
    return @ptrCast(@alignCast(userdata.?));
}

fn simOf(userdata: ?*anyopaque) *Sim {
    return hostOf(userdata).sim;
}

fn crashHandler(userdata: ?*anyopaque) void {
    _ = userdata;
}

fn async(
    userdata: ?*anyopaque,
    result: []u8,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) ?*Io.AnyFuture {
    const h = hostOf(userdata);
    return h.sim.concurrent(h, result.len, result_alignment, context, context_alignment, start) catch {
        // No unit of concurrency: run it now into the eager result.
        start(context.ptr, result.ptr);
        return null;
    };
}

fn concurrent(
    userdata: ?*anyopaque,
    result_len: usize,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) Io.ConcurrentError!*Io.AnyFuture {
    const h = hostOf(userdata);
    return h.sim.concurrent(h, result_len, result_alignment, context, context_alignment, start);
}

fn await(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, result_alignment: Alignment) void {
    simOf(userdata).await(any_future, result, result_alignment);
}

fn cancel(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, result_alignment: Alignment) void {
    simOf(userdata).cancel(any_future, result, result_alignment);
}

fn groupAsync(
    userdata: ?*anyopaque,
    group: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) void {
    const h = hostOf(userdata);
    h.sim.groupAsync(h, group, context, context_alignment, start);
}

fn groupConcurrent(
    userdata: ?*anyopaque,
    group: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) Io.ConcurrentError!void {
    const h = hostOf(userdata);
    return h.sim.groupConcurrent(h, group, context, context_alignment, start);
}

fn groupAwait(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) Io.Cancelable!void {
    return simOf(userdata).groupAwait(group, token);
}

fn groupCancel(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) void {
    simOf(userdata).groupCancel(group, token);
}

fn recancel(userdata: ?*anyopaque) void {
    simOf(userdata).recancel();
}

fn swapCancelProtection(userdata: ?*anyopaque, new: Io.CancelProtection) Io.CancelProtection {
    return simOf(userdata).swapCancelProtection(new);
}

fn checkCancel(userdata: ?*anyopaque) Io.Cancelable!void {
    return simOf(userdata).checkCancel();
}

fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: Io.Timeout) Io.Cancelable!void {
    return simOf(userdata).futexWait(ptr, expected, timeout, true);
}

fn futexWaitUncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
    simOf(userdata).futexWait(ptr, expected, .none, false) catch unreachable; // not cancelable
}

fn futexWake(userdata: ?*anyopaque, ptr: *const u32, max_waiters: u32) void {
    simOf(userdata).futexWake(ptr, max_waiters);
}

fn now(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
    const h = hostOf(userdata);
    if (h.sim.current) |me| h.sim.maybeYield(me);
    return .{ .nanoseconds = h.clockNs(clock) };
}

fn clockResolution(userdata: ?*anyopaque, clock: Io.Clock) Io.Clock.ResolutionError!Io.Duration {
    _ = userdata;
    _ = clock;
    return .fromNanoseconds(1);
}

fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
    return simOf(userdata).sleep(timeout);
}

fn random(userdata: ?*anyopaque, buffer: []u8) void {
    const h = hostOf(userdata);
    h.sim.random(h, buffer);
}

/// Seeded like `random`: a simulated host has no secrets worth protecting,
/// and a draw that changed between runs would break replay.
fn randomSecure(userdata: ?*anyopaque, buffer: []u8) Io.RandomSecureError!void {
    const h = hostOf(userdata);
    h.sim.random(h, buffer);
}

// ── operations and batches ────────────────────────────────────────────────

fn operate(userdata: ?*anyopaque, operation: Io.Operation) Io.Cancelable!Io.Operation.Result {
    const h = hostOf(userdata);
    return switch (operation) {
        .net_receive => |op| .{ .net_receive = try h.sim.net.receive(h, op) },
        .file_read_streaming => |op| blk: {
            if (h.sim.current) |me| try h.sim.cancelPoint(me);
            break :blk .{ .file_read_streaming = h.fs.readStreaming(op.file, op.data) };
        },
        .file_write_streaming => |op| blk: {
            if (h.sim.current) |me| try h.sim.cancelPoint(me);
            break :blk .{ .file_write_streaming = h.fs.writeStreaming(op.file, op.header, op.data, op.splat) };
        },
        else => Io.failing.vtable.operate(null, operation),
    };
}

/// Completes `operation` now if it would not block; null otherwise.
fn tryOperate(h: *Host, operation: Io.Operation) ?Io.Operation.Result {
    return switch (operation) {
        .net_receive => |op| if (h.sim.net.tryReceive(h, op)) |r| .{ .net_receive = r } else null,
        .file_read_streaming => |op| .{ .file_read_streaming = h.fs.readStreaming(op.file, op.data) },
        .file_write_streaming => |op| .{ .file_write_streaming = h.fs.writeStreaming(op.file, op.header, op.data, op.splat) },
        else => Io.failing.vtable.operate(null, operation) catch unreachable, // `failing` never cancels
    };
}

/// Moves every submitted operation that can complete now to `completed`.
/// Operations that would block stay submitted, so `Batch.cancel` (which
/// aborts submissions) needs nothing from the implementation.
fn completeReady(h: *Host, batch: *Io.Batch) bool {
    var progressed = false;
    var prev: Io.Operation.OptionalIndex = .none;
    var idx = batch.submitted.head;
    while (idx != .none) {
        const i = idx.toIndex();
        const sub = batch.storage[i].submission;
        const next = sub.node.next;
        if (tryOperate(h, sub.operation)) |result| {
            switch (prev) {
                .none => batch.submitted.head = next,
                else => |p| batch.storage[p.toIndex()].submission.node.next = next,
            }
            if (batch.submitted.tail == idx) batch.submitted.tail = prev;
            batch.storage[i] = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
            switch (batch.completed.tail) {
                .none => batch.completed.head = idx,
                else => |t| batch.storage[t.toIndex()].completion.node.next = idx,
            }
            batch.completed.tail = idx;
            progressed = true;
        } else prev = idx;
        idx = next;
    }
    return progressed;
}

fn batchWait(h: *Host, batch: *Io.Batch, timeout: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
    const sim = h.sim;
    const me = sim.running();
    try sim.cancelPoint(me);
    const deadline = sim.deadlineOf(h, timeout);
    while (true) {
        if (completeReady(h, batch)) return;
        if (batch.submitted.head == .none) return;
        const reason = sim.net.waitBatch(h, me, batch, deadline) catch return error.ConcurrencyUnavailable;
        switch (reason) {
            .canceled => {
                me.acknowledgeCancel();
                return error.Canceled;
            },
            .timeout => return if (completeReady(h, batch)) {} else error.Timeout,
            .normal => {},
        }
    }
}

fn batchAwaitAsync(userdata: ?*anyopaque, batch: *Io.Batch) Io.Cancelable!void {
    return batchWait(hostOf(userdata), batch, .none) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.Timeout, error.ConcurrencyUnavailable => {}, // no deadline; out of memory acts as a spurious wakeup
    };
}

fn batchAwaitConcurrent(userdata: ?*anyopaque, batch: *Io.Batch, timeout: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
    return batchWait(hostOf(userdata), batch, timeout);
}

fn batchCancel(userdata: ?*anyopaque, batch: *Io.Batch) void {
    _ = userdata;
    _ = batch; // nothing is ever left pending: see `completeReady`
}

// ── network ───────────────────────────────────────────────────────────────

fn netListenIp(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ListenOptions) net.IpAddress.ListenError!net.Socket {
    const h = hostOf(userdata);
    return h.sim.net.listen(h, address, options);
}

fn netAccept(userdata: ?*anyopaque, server: net.Socket.Handle, options: net.Server.AcceptOptions) net.Server.AcceptError!net.Socket {
    _ = options;
    const h = hostOf(userdata);
    return h.sim.net.accept(h, server);
}

fn netBindIp(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
    const h = hostOf(userdata);
    return h.sim.net.bind(h, address, options);
}

fn netConnectIp(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
    const h = hostOf(userdata);
    return h.sim.net.connect(h, address, options);
}

fn netSend(userdata: ?*anyopaque, handle: net.Socket.Handle, messages: []net.OutgoingMessage, flags: net.SendFlags) struct { ?net.Socket.SendError, usize } {
    _ = flags;
    const h = hostOf(userdata);
    const err, const n = h.sim.net.send(h, handle, messages);
    return .{ err, n };
}

fn netRead(userdata: ?*anyopaque, src: net.Socket.Handle, data: [][]u8) net.Stream.Reader.Error!usize {
    const h = hostOf(userdata);
    return h.sim.net.read(h, src, data);
}

fn netWrite(userdata: ?*anyopaque, dest: net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) net.Stream.Writer.Error!usize {
    const h = hostOf(userdata);
    return h.sim.net.write(h, dest, header, data, splat);
}

fn netClose(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
    const h = hostOf(userdata);
    h.sim.net.close(h, handles);
}

fn netShutdown(userdata: ?*anyopaque, handle: net.Socket.Handle, how: net.ShutdownHow) net.ShutdownError!void {
    const h = hostOf(userdata);
    return h.sim.net.shutdown(h, handle, how);
}

// ── file system ───────────────────────────────────────────────────────────

/// Every file system entry is a preemption point, as a blocking disk call
/// is: another task may run while this one waits for the disk.
fn fsOf(userdata: ?*anyopaque) *@import("fs.zig").Fs {
    const h = hostOf(userdata);
    if (h.sim.current) |me| h.sim.maybeYield(me);
    return &h.fs;
}

fn dirCreateDir(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirError!void {
    return fsOf(userdata).createDir(dir, sub_path, permissions);
}

fn dirCreateDirPath(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirPathError!Dir.CreatePathStatus {
    return fsOf(userdata).createDirPath(dir, sub_path, permissions);
}

fn dirCreateDirPathOpen(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions, options: Dir.OpenOptions) Dir.CreateDirPathOpenError!Dir {
    return fsOf(userdata).createDirPathOpen(dir, sub_path, permissions, options);
}

fn dirOpenDir(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.OpenOptions) Dir.OpenError!Dir {
    return fsOf(userdata).openDir(dir, sub_path, options);
}

fn dirStat(userdata: ?*anyopaque, dir: Dir) Dir.StatError!Dir.Stat {
    return fsOf(userdata).statDir(dir);
}

fn dirStatFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.StatFileOptions) Dir.StatFileError!File.Stat {
    return fsOf(userdata).statFile(dir, sub_path, options.follow_symlinks);
}

fn dirAccess(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.AccessOptions) Dir.AccessError!void {
    _ = options;
    return fsOf(userdata).access(dir, sub_path);
}

fn dirCreateFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.CreateFileOptions) File.OpenError!File {
    return fsOf(userdata).createFile(dir, sub_path, options);
}

fn dirCreateFileAtomic(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.CreateFileAtomicOptions) Dir.CreateFileAtomicError!File.Atomic {
    return fsOf(userdata).createFileAtomic(dir, sub_path, options);
}

fn dirOpenFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.OpenFileOptions) File.OpenError!File {
    return fsOf(userdata).openFile(dir, sub_path, options);
}

fn dirClose(userdata: ?*anyopaque, dirs: []const Dir) void {
    fsOf(userdata).closeDirs(dirs);
}

fn dirRead(userdata: ?*anyopaque, reader: *Dir.Reader, entries: []Dir.Entry) Dir.Reader.Error!usize {
    return fsOf(userdata).read(reader, entries);
}

fn dirRealPath(userdata: ?*anyopaque, dir: Dir, out_buffer: []u8) Dir.RealPathError!usize {
    return fsOf(userdata).realPath(dir, null, out_buffer);
}

fn dirRealPathFile(userdata: ?*anyopaque, dir: Dir, path_name: []const u8, out_buffer: []u8) Dir.RealPathFileError!usize {
    return fsOf(userdata).realPath(dir, path_name, out_buffer);
}

fn dirDeleteFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteFileError!void {
    return fsOf(userdata).deleteFile(dir, sub_path);
}

fn dirDeleteDir(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteDirError!void {
    return fsOf(userdata).deleteDir(dir, sub_path);
}

fn dirRename(userdata: ?*anyopaque, old_dir: Dir, old_sub_path: []const u8, new_dir: Dir, new_sub_path: []const u8) Dir.RenameError!void {
    return fsOf(userdata).rename(old_dir, old_sub_path, new_dir, new_sub_path, true) catch |err| switch (err) {
        error.PathAlreadyExists, error.OperationUnsupported => unreachable, // only without replacing
        else => |e| e,
    };
}

fn dirRenamePreserve(userdata: ?*anyopaque, old_dir: Dir, old_sub_path: []const u8, new_dir: Dir, new_sub_path: []const u8) Dir.RenamePreserveError!void {
    return fsOf(userdata).rename(old_dir, old_sub_path, new_dir, new_sub_path, false);
}

fn fileStat(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    return fsOf(userdata).stat(file);
}

fn fileLength(userdata: ?*anyopaque, file: File) File.LengthError!u64 {
    return fsOf(userdata).length(file);
}

fn fileClose(userdata: ?*anyopaque, files: []const File) void {
    fsOf(userdata).closeFiles(files);
}

fn fileWritePositional(userdata: ?*anyopaque, file: File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) File.WritePositionalError!usize {
    return fsOf(userdata).writeAtFile(file, header, data, splat, offset);
}

fn fileReadPositional(userdata: ?*anyopaque, file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
    return fsOf(userdata).readAt(file, data, offset);
}

fn fileSeekBy(userdata: ?*anyopaque, file: File, relative_offset: i64) File.SeekError!void {
    return fsOf(userdata).seekBy(file, relative_offset);
}

fn fileSeekTo(userdata: ?*anyopaque, file: File, absolute_offset: u64) File.SeekError!void {
    return fsOf(userdata).seekTo(file, absolute_offset);
}

fn fileSync(userdata: ?*anyopaque, file: File) File.SyncError!void {
    return fsOf(userdata).sync(file);
}

fn fileIsTty(userdata: ?*anyopaque, file: File) Io.Cancelable!bool {
    _ = userdata;
    _ = file;
    return false;
}

fn fileSetLength(userdata: ?*anyopaque, file: File, length: u64) File.SetLengthError!void {
    return fsOf(userdata).setLength(file, length);
}

fn fileLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!void {
    return fsOf(userdata).acquireLock(file, lock, true) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.WouldBlock => error.SystemResources, // the handle was closed meanwhile
    };
}

fn fileTryLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!bool {
    fsOf(userdata).acquireLock(file, lock, false) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.WouldBlock => return false,
    };
    return true;
}

fn fileUnlock(userdata: ?*anyopaque, file: File) void {
    fsOf(userdata).unlock(file);
}

fn fileDowngradeLock(userdata: ?*anyopaque, file: File) File.DowngradeLockError!void {
    fsOf(userdata).downgrade(file);
}

/// Names resolve against the simulation's hosts (`HostOptions.name`), plus
/// IP literals and `localhost` (this host's loopback addresses). Nothing
/// else exists: an unknown name is `UnknownHostName`, never a query on the
/// real network.
fn netLookup(
    userdata: ?*anyopaque,
    host_name: net.HostName,
    resolved: *Io.Queue(net.HostName.LookupResult),
    options: net.HostName.LookupOptions,
) net.HostName.LookupError!void {
    const h = hostOf(userdata);
    const io = h.io();
    defer resolved.close(io);
    netLookupInner(h, io, host_name.bytes, resolved, options) catch |err| switch (err) {
        error.Closed => unreachable, // `resolved` must not be closed until `netLookup` returns
        else => |e| return e,
    };
}

fn netLookupInner(
    h: *Host,
    io: Io,
    name: []const u8,
    resolved: *Io.Queue(net.HostName.LookupResult),
    options: net.HostName.LookupOptions,
) (net.HostName.LookupError || Io.QueueClosedError)!void {
    try h.sim.cancelPoint(h.sim.running());
    var addrs: [2]net.IpAddress = undefined;
    var n: usize = 0;
    if (net.IpAddress.parse(name, options.port)) |addr| {
        addrs[0] = addr;
        n = 1;
    } else |_| {
        const v4: [4]u8, const v6: [16]u8 = if (std.ascii.eqlIgnoreCase(name, "localhost") or std.ascii.eqlIgnoreCase(name, "localhost."))
            .{ .{ 127, 0, 0, 1 }, .{0} ** 15 ++ .{1} }
        else if (h.sim.hostByName(name)) |target|
            .{ target.ip4, target.ip6 }
        else
            return error.UnknownHostName;
        addrs[0] = .{ .ip4 = .{ .bytes = v4, .port = options.port } };
        addrs[1] = .{ .ip6 = .{ .bytes = v6, .port = options.port } };
        n = 2;
    }
    var any = false;
    for (addrs[0..n]) |addr| {
        if (options.family) |fam| if (fam != @as(net.IpAddress.Family, addr)) continue;
        try resolved.putOne(io, .{ .address = addr });
        any = true;
    }
    if (!any) return error.UnknownHostName;
    if (options.canonical_name_buffer) |buf| {
        @memcpy(buf[0..name.len], name);
        try resolved.putOne(io, .{ .canonical_name = .{ .bytes = buf[0..name.len] } });
    }
}

fn netListenUnix(userdata: ?*anyopaque, address: *const net.UnixAddress, options: net.UnixAddress.ListenOptions) net.UnixAddress.ListenError!net.Socket.Handle {
    const h = hostOf(userdata);
    return h.sim.net.listenUnix(h, address, options);
}

fn netConnectUnix(userdata: ?*anyopaque, address: *const net.UnixAddress) net.UnixAddress.ConnectError!net.Socket.Handle {
    const h = hostOf(userdata);
    return h.sim.net.connectUnix(h, address);
}

// ── links and metadata ─────────────────────────────────────────────────────

fn dirSymLink(userdata: ?*anyopaque, dir: Dir, target_path: []const u8, sym_link_path: []const u8, flags: Dir.SymLinkFlags) Dir.SymLinkError!void {
    _ = flags;
    return fsOf(userdata).symLink(dir, target_path, sym_link_path);
}

fn dirReadLink(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    return fsOf(userdata).readLink(dir, sub_path, buffer);
}

fn dirHardLink(userdata: ?*anyopaque, old_dir: Dir, old_sub_path: []const u8, new_dir: Dir, new_sub_path: []const u8, options: Dir.HardLinkOptions) Dir.HardLinkError!void {
    return fsOf(userdata).hardLink(old_dir, old_sub_path, new_dir, new_sub_path, options.follow_symlinks);
}

fn fileHardLink(userdata: ?*anyopaque, file: File, new_dir: Dir, new_sub_path: []const u8, options: File.HardLinkOptions) File.HardLinkError!void {
    _ = options;
    return fsOf(userdata).fileHardLink(file, new_dir, new_sub_path);
}

fn fileRealPath(userdata: ?*anyopaque, file: File, out_buffer: []u8) File.RealPathError!usize {
    return fsOf(userdata).fileRealPath(file, out_buffer);
}

fn dirSetPermissions(userdata: ?*anyopaque, dir: Dir, permissions: Dir.Permissions) Dir.SetPermissionsError!void {
    const fs = fsOf(userdata);
    fs.setPermissions(fs.nodeAt(dir, null, true) catch return error.FileNotFound, permissions);
}

fn dirSetFilePermissions(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: File.Permissions, options: Dir.SetFilePermissionsOptions) Dir.SetFilePermissionsError!void {
    const fs = fsOf(userdata);
    fs.setPermissions(fs.nodeAt(dir, sub_path, options.follow_symlinks) catch |err| return switch (err) {
        error.NotDir => error.FileNotFound,
        else => |e| e,
    }, permissions);
}

fn fileSetPermissions(userdata: ?*anyopaque, file: File, permissions: File.Permissions) File.SetPermissionsError!void {
    const fs = fsOf(userdata);
    fs.setPermissions(fs.nodeOfFile(file) orelse return error.AccessDenied, permissions);
}

fn dirSetOwner(userdata: ?*anyopaque, dir: Dir, uid: ?File.Uid, gid: ?File.Gid) Dir.SetOwnerError!void {
    const fs = fsOf(userdata);
    fs.setOwner(fs.nodeAt(dir, null, true) catch return error.AccessDenied, uid, gid);
}

fn dirSetFileOwner(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, uid: ?File.Uid, gid: ?File.Gid, options: Dir.SetFileOwnerOptions) Dir.SetFileOwnerError!void {
    const fs = fsOf(userdata);
    // `Dir.SetFileOwnerError` has no tag for a missing path.
    fs.setOwner(fs.nodeAt(dir, sub_path, options.follow_symlinks) catch |err| return switch (err) {
        error.BadPathName => error.BadPathName,
        else => error.AccessDenied,
    }, uid, gid);
}

fn fileSetOwner(userdata: ?*anyopaque, file: File, uid: ?File.Uid, gid: ?File.Gid) File.SetOwnerError!void {
    const fs = fsOf(userdata);
    fs.setOwner(fs.nodeOfFile(file) orelse return error.AccessDenied, uid, gid);
}

fn dirSetTimestamps(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.SetTimestampsOptions) Dir.SetTimestampsError!void {
    const fs = fsOf(userdata);
    // `Dir.SetTimestampsError` has no tag for a missing path either.
    fs.setTimestamps(fs.nodeAt(dir, sub_path, options.follow_symlinks) catch |err| return switch (err) {
        error.BadPathName => error.BadPathName,
        else => error.AccessDenied,
    }, options.access_timestamp, options.modify_timestamp);
}

fn fileSetTimestamps(userdata: ?*anyopaque, file: File, options: File.SetTimestampsOptions) File.SetTimestampsError!void {
    const fs = fsOf(userdata);
    fs.setTimestamps(fs.nodeOfFile(file) orelse return error.AccessDenied, options.access_timestamp, options.modify_timestamp);
}

// ── memory maps ────────────────────────────────────────────────────────────
//
// The "file operations" mapping `File.MemoryMap` allows: memory is a copy of
// the file that `read` refreshes and `write` puts back, so every byte goes
// through the simulated disk (faults, the crash model). The copy comes from
// the host's allocator, which a crash releases with the host.

const page = std.heap.page_size_min;

fn fileMemoryMapCreate(userdata: ?*anyopaque, file: File, options: File.MemoryMap.CreateOptions) File.MemoryMap.CreateError!File.MemoryMap {
    const h = hostOf(userdata);
    const node = h.fs.nodeOfFile(file) orelse return error.AccessDenied;
    if (node.kind != .file) return error.AccessDenied;
    const memory = try h.allocator().alignedAlloc(u8, .fromByteUnits(page), options.len);
    @memset(memory, 0);
    var mm: File.MemoryMap = .{ .file = file, .offset = options.offset, .memory = memory, .section = {} };
    fileMemoryMapRead(userdata, &mm) catch |err| {
        h.allocator().free(memory);
        return err;
    };
    return mm;
}

fn fileMemoryMapDestroy(userdata: ?*anyopaque, mm: *File.MemoryMap) void {
    hostOf(userdata).allocator().free(mm.memory);
    mm.* = undefined;
}

fn fileMemoryMapSetLength(userdata: ?*anyopaque, mm: *File.MemoryMap, len: usize) File.MemoryMap.SetLengthError!void {
    _ = userdata;
    _ = mm;
    _ = len;
    return error.OperationUnsupported; // the documented answer: destroy and create
}

fn fileMemoryMapRead(userdata: ?*anyopaque, mm: *File.MemoryMap) File.ReadPositionalError!void {
    const fs = fsOf(userdata);
    var done: usize = 0;
    while (done < mm.memory.len) {
        const n = try fs.readAt(mm.file, &.{mm.memory[done..]}, mm.offset + done);
        if (n == 0) break;
        done += n;
    }
    @memset(mm.memory[done..], 0); // past the file's end
}

fn fileMemoryMapWrite(userdata: ?*anyopaque, mm: *File.MemoryMap) File.WritePositionalError!void {
    const fs = fsOf(userdata);
    var done: usize = 0;
    while (done < mm.memory.len) {
        done += try fs.writeAtFile(mm.file, "", &.{mm.memory[done..]}, 1, mm.offset + done);
    }
}
