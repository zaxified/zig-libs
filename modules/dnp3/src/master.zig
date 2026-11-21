// SPDX-License-Identifier: MIT
//! dnp3.master — the stateful master session (IEEE 1815-2012 §4, the master
//! half of the application layer): a prioritised task queue (startup
//! sequence, integrity and class polls, IIN-driven tasks, commands), one
//! request outstanding at a time with a response timeout and retries, CONFIRM
//! of responses and unsolicited responses, and unsolicited-response
//! duplicate suppression. Like the `outstation` it is allocation-free, owns
//! no timer and does no I/O: the caller injects `now_ms` (milliseconds since
//! the UNIX epoch, the same clock the outstation stamps events with), asks
//! `poll` for the next request fragment to send, feeds every received
//! application fragment to `handle`, and sleeps until `nextWakeup`. The
//! codecs it is built from are the same ones the outstation uses, and the
//! module's tests drive it against the real `outstation.Outstation`.
//!
//! ## What it does by itself
//! - **Startup** (`Config`, the opendnp3 sequence): DISABLE_UNSOLICITED for
//!   classes 1-3, an integrity poll (g60v2/v3/v4/v1), then ENABLE_UNSOLICITED.
//! - **Periodic scans**: `integrity_poll_ms`, `class_poll_ms[class]`.
//! - **IIN-driven tasks** on any response: restart -> WRITE g80v1 clear
//!   (`clear_restart_iin`), class 1/2/3 events -> a class poll
//!   (`scan_on_event_iin`), NEED_TIME -> time sync (`time_sync`: `lan` writes
//!   the clock, `non_lan` measures the delay first and adds half of it).
//! - **Commands** (`queueCommand`): direct operate, or select-before-operate
//!   as two requests (SELECT, then OPERATE at the next sequence number on
//!   success), CROB (g12v1) and analog output block (g41v1-v4); the outstation's
//!   echo status is reported as `Event.command_done`.
//! - **CONFIRM** of every response and unsolicited response that asks for it
//!   (CON bit), with the right sequence number and UNS bit; a repeated
//!   unsolicited response (same sequence number as the last) is confirmed
//!   again and not delivered a second time.
//! - **Timeouts**: no response within `response_timeout_ms` fails the task; it
//!   is retried after `task_retry_ms`, `max_task_retries` times (a periodic
//!   task is then simply rescheduled, a command reports `timeout`).
//!
//! ## What the caller does
//! Frame the fragments (`transport`/`link`, or `outstation.Session`-style
//! code on its own side), and read the measurements out of `Data.objects` with
//! `Measurements`, which walks the object headers and ranges, applies g51
//! common times of occurrence and yields one `Measurement` per point.

const std = @import("std");
const application = @import("application.zig");
const objects = @import("objects.zig");
const records = @import("records.zig");
const link = @import("link.zig");
const transport = @import("transport.zig");
const link_session = @import("link_session.zig");

const Iin = application.Iin;

pub const Error = error{
    /// The output buffer cannot hold the request.
    BufferTooSmall,
    /// `queueCommand`: the command queue is full.
    QueueFull,
};

pub const TimeSync = enum {
    /// Never write the outstation's clock.
    none,
    /// Write the master's time as it is (a LAN: the delay is negligible).
    lan,
    /// Measure the round trip with DELAY_MEASURE first and write
    /// `now + delay / 2` (IEEE 1815-2012 §5.1.5, the non-LAN procedure).
    non_lan,
};

pub const Config = struct {
    /// How long to wait for a response (a fragment of it) before the task fails.
    response_timeout_ms: u64 = 5_000,
    /// DISABLE_UNSOLICITED (classes 1-3) before anything else at startup.
    disable_unsolicited_on_startup: bool = true,
    /// An integrity poll after startup.
    startup_integrity_poll: bool = true,
    /// ENABLE_UNSOLICITED (classes 1-3) once the startup integrity poll is done.
    enable_unsolicited_on_startup: bool = true,
    /// Repeat the integrity poll this often (null: only at startup / on demand).
    integrity_poll_ms: ?u64 = null,
    /// Poll class 1, 2, 3 events this often (null: only on the IIN bit).
    class_poll_ms: [3]?u64 = .{ null, null, null },
    /// Poll a class when a response's IIN says it has events.
    scan_on_event_iin: bool = true,
    /// Clear the outstation's restart IIN (WRITE g80v1 index 7).
    clear_restart_iin: bool = true,
    time_sync: TimeSync = .none,
    /// Wait this long before retrying a failed task.
    task_retry_ms: u64 = 5_000,
    /// Retries of a failed task before it is dropped.
    max_task_retries: u8 = 3,
};

/// The tasks, lowest value = highest priority.
pub const TaskKind = enum(u8) {
    command,
    clear_restart,
    disable_unsolicited,
    delay_measure,
    write_time,
    integrity_poll,
    enable_unsolicited,
    class_poll_1,
    class_poll_2,
    class_poll_3,
};

const n_tasks = @backingInt(TaskKind.class_poll_3) + 1;

pub const CommandBody = union(enum) {
    crob: objects.g12.V1,
    analog_i16: i16,
    analog_i32: i32,
    analog_f32: f32,
    analog_f64: f64,
};

pub const Command = struct {
    /// false: DIRECT_OPERATE. true: SELECT, then OPERATE once the SELECT succeeded.
    select_before_operate: bool = false,
    index: u16,
    body: CommandBody,
};

/// One decoded point from a response.
pub const Measurement = struct {
    kind: records.PointKind,
    /// True for an event object, false for a static one.
    event: bool,
    index: u32,
    value: records.Value,
    flags: records.Flags,
    /// Absolute time of an event with an absolute time, or the g51 common
    /// time plus the relative offset of a relative-time event.
    time_ms: ?u64,
};

/// Received point data, borrowed from the fragment given to `handle`.
pub const Data = struct {
    unsolicited: bool,
    iin: Iin,
    /// The object headers and records of this fragment.
    objects: []const u8,
    /// The fragment is the last of its response.
    final: bool,

    pub fn measurements(self: Data) Measurements {
        return .{ .rest = self.objects };
    }
};

pub const Event = union(enum) {
    /// A task finished: `ok = false` after its retries ran out.
    task_done: struct { kind: TaskKind, ok: bool },
    /// A command finished with the outstation's status (`timeout` when no
    /// response ever came, `format_error` for a response that did not echo
    /// the command).
    command_done: struct { index: u16, status: objects.g12.CommandStatus },
};

pub const Poll = struct {
    /// The request fragment to send (in the caller's `out` buffer).
    request: ?[]const u8 = null,
    event: ?Event = null,
};

pub const Handled = struct {
    /// A CONFIRM fragment to send (in the caller's `out` buffer).
    confirm: ?[]const u8 = null,
    data: ?Data = null,
    event: ?Event = null,
};

const cmd_queue_len = 8;

pub const Master = struct {
    cfg: Config,
    /// The IIN of the last response.
    iin: Iin = .{},
    /// Per task: when it is next due (null: not scheduled).
    due: [n_tasks]?u64 = @splat(null),
    state: enum { idle, wait_response } = .idle,
    current: TaskKind = .integrity_poll,
    /// Sequence number of the next request, and of the one outstanding.
    seq: u4 = 0,
    req_seq: u4 = 0,
    deadline_ms: u64 = 0,
    retries: u8 = 0,
    /// The next fragment of a multi-fragment response must carry this sequence number.
    expect_frag_seq: ?u4 = null,
    last_uns_seq: ?u4 = null,
    startup_pending: bool = true,
    delay_ms: u16 = 0,
    queue: [cmd_queue_len]Command = undefined,
    q_head: u8 = 0,
    q_len: u8 = 0,
    /// The command in flight and its phase (`select` before `operate`).
    cmd: ?Command = null,
    cmd_operate_phase: bool = false,
    started: bool = false,

    pub fn init(cfg: Config) Master {
        return .{ .cfg = cfg };
    }

    // ── scheduling ──────────────────────────────────────────────────────────

    fn schedule(self: *Master, kind: TaskKind, at: u64) void {
        const i = @backingInt(kind);
        if (self.due[i] == null or at < self.due[i].?) self.due[i] = at;
    }

    fn start(self: *Master, now_ms: u64) void {
        self.started = true;
        if (self.cfg.disable_unsolicited_on_startup) {
            self.schedule(.disable_unsolicited, now_ms);
        } else self.afterDisable(now_ms);
        if (self.cfg.integrity_poll_ms) |p| self.schedule(.integrity_poll, now_ms + p);
        for (self.cfg.class_poll_ms, 0..) |maybe, c| {
            if (maybe) |p| self.schedule(@fromBackingInt(@intCast(@backingInt(TaskKind.class_poll_1) + c)), now_ms + p);
        }
    }

    fn afterDisable(self: *Master, now_ms: u64) void {
        if (self.cfg.startup_integrity_poll) {
            self.schedule(.integrity_poll, now_ms);
        } else self.afterIntegrity(now_ms);
    }

    fn afterIntegrity(self: *Master, now_ms: u64) void {
        if (self.startup_pending) {
            self.startup_pending = false;
            if (self.cfg.enable_unsolicited_on_startup) self.schedule(.enable_unsolicited, now_ms);
        }
    }

    /// Ask for an integrity poll now.
    pub fn integrityPoll(self: *Master, now_ms: u64) void {
        self.schedule(.integrity_poll, now_ms);
    }

    /// Ask for a class 1, 2 or 3 event poll now.
    pub fn classPoll(self: *Master, class: u2, now_ms: u64) void {
        if (class == 0) return self.integrityPoll(now_ms);
        self.schedule(@fromBackingInt(@intCast(@backingInt(TaskKind.class_poll_1) + class - 1)), now_ms);
    }

    pub fn queueCommand(self: *Master, c: Command) Error!void {
        if (self.q_len == cmd_queue_len) return error.QueueFull;
        self.queue[(self.q_head + self.q_len) % cmd_queue_len] = c;
        self.q_len += 1;
    }

    /// When `poll` next has something to do: the outstanding request's deadline
    /// or the earliest due task; null when nothing is scheduled.
    pub fn nextWakeup(self: *const Master) ?u64 {
        if (self.state == .wait_response) return self.deadline_ms;
        var best: ?u64 = null;
        if (self.q_len != 0) return 0;
        for (self.due) |d| {
            if (d) |t| best = if (best) |b| @min(b, t) else t;
        }
        return best;
    }

    fn applyIin(self: *Master, iin: Iin, now_ms: u64) void {
        self.iin = iin;
        if (iin.device_restart and self.cfg.clear_restart_iin) self.schedule(.clear_restart, now_ms);
        if (iin.need_time and self.cfg.time_sync != .none) {
            self.schedule(if (self.cfg.time_sync == .non_lan) .delay_measure else .write_time, now_ms);
        }
        if (self.cfg.scan_on_event_iin) {
            if (iin.class_1_events) self.schedule(.class_poll_1, now_ms);
            if (iin.class_2_events) self.schedule(.class_poll_2, now_ms);
            if (iin.class_3_events) self.schedule(.class_poll_3, now_ms);
        }
    }

    // ── requests ────────────────────────────────────────────────────────────

    /// The next request to send, or a timeout event, or nothing. Call it
    /// whenever time has passed (at `nextWakeup`) and after `handle`.
    pub fn poll(self: *Master, now_ms: u64, out: []u8) Error!Poll {
        if (!self.started) self.start(now_ms);
        if (self.state == .wait_response) {
            if (now_ms < self.deadline_ms) return .{};
            return .{ .event = self.failCurrent(now_ms) };
        }
        const kind = self.nextDue(now_ms) orelse return .{};
        const request = try self.build(kind, now_ms, out);
        self.state = .wait_response;
        self.current = kind;
        self.deadline_ms = now_ms + self.cfg.response_timeout_ms;
        self.expect_frag_seq = null;
        return .{ .request = request };
    }

    fn nextDue(self: *Master, now_ms: u64) ?TaskKind {
        if (self.q_len != 0 or self.cmd != null) return .command;
        for (self.due, 0..) |d, i| {
            if (d) |t| if (t <= now_ms) return @fromBackingInt(@intCast(i));
        }
        return null;
    }

    fn header(self: *Master, function: application.FunctionCode, out: []u8) Error!usize {
        const h = application.encodeRequestHeader(
            .{ .control = .{ .fir = true, .fin = true, .seq = self.seq }, .function = function },
            out,
        ) catch return error.BufferTooSmall;
        self.req_seq = self.seq;
        self.seq +%= 1;
        return h.len;
    }

    fn addHeader(g: u8, v: u8, q: objects.Qualifier, range: objects.Range, out: []u8, pos: *usize) Error!void {
        const h = objects.encodeObjectHeader(.{ .group = g, .variation = v, .qualifier = q, .range = range }, out[pos.*..]) catch return error.BufferTooSmall;
        pos.* += h.len;
    }

    const all_values: objects.Qualifier = .{ .prefix_code = .none, .range_code = .all_values };

    fn build(self: *Master, kind: TaskKind, now_ms: u64, out: []u8) Error![]const u8 {
        var pos: usize = 0;
        switch (kind) {
            .disable_unsolicited, .enable_unsolicited => {
                pos = try self.header(if (kind == .enable_unsolicited) .enable_unsolicited else .disable_unsolicited, out);
                for ([_]u8{ 2, 3, 4 }) |v| try addHeader(60, v, all_values, .{ .all_values = {} }, out, &pos);
            },
            .integrity_poll => {
                pos = try self.header(.read, out);
                for ([_]u8{ 2, 3, 4, 1 }) |v| try addHeader(60, v, all_values, .{ .all_values = {} }, out, &pos);
            },
            .class_poll_1, .class_poll_2, .class_poll_3 => {
                pos = try self.header(.read, out);
                try addHeader(60, @backingInt(kind) - @backingInt(TaskKind.class_poll_1) + 2, all_values, .{ .all_values = {} }, out, &pos);
            },
            .clear_restart => {
                pos = try self.header(.write, out);
                try addHeader(80, 1, .{ .prefix_code = .none, .range_code = .start_stop_1b }, .{ .start_stop = .{ .start = 7, .stop = 7 } }, out, &pos);
                if (out.len < pos + 1) return error.BufferTooSmall;
                out[pos] = 0; // the restart bit, cleared
                pos += 1;
            },
            .delay_measure => pos = try self.header(.delay_measure, out),
            .write_time => {
                pos = try self.header(.write, out);
                try addHeader(50, 1, .{ .prefix_code = .none, .range_code = .count_1b }, .{ .count = 1 }, out, &pos);
                const t = now_ms + (if (self.cfg.time_sync == .non_lan) self.delay_ms / 2 else 0);
                const tb = (objects.g50.V1{ .ms_since_epoch = t }).encode(out[pos..]) catch return error.BufferTooSmall;
                pos += tb.len;
            },
            .command => {
                if (self.cmd == null) {
                    self.cmd = self.queue[self.q_head];
                    self.q_head = (self.q_head + 1) % cmd_queue_len;
                    self.q_len -= 1;
                    self.cmd_operate_phase = false;
                }
                const c = self.cmd.?;
                const function: application.FunctionCode = if (!c.select_before_operate)
                    .direct_operate
                else if (self.cmd_operate_phase) .operate else .select;
                pos = try self.header(function, out);
                try encodeCommand(c, out, &pos);
            },
        }
        return out[0..pos];
    }

    fn encodeCommand(c: Command, out: []u8, pos: *usize) Error!void {
        const wide = c.index > 0xFF;
        const q: objects.Qualifier = .{ .prefix_code = if (wide) .index_2b else .index_1b, .range_code = if (wide) .count_2b else .count_1b };
        const g: u8, const v: u8 = switch (c.body) {
            .crob => .{ 12, 1 },
            .analog_i32 => .{ 41, 1 },
            .analog_i16 => .{ 41, 2 },
            .analog_f32 => .{ 41, 3 },
            .analog_f64 => .{ 41, 4 },
        };
        try addHeader(g, v, q, .{ .count = 1 }, out, pos);
        const idx_len: usize = if (wide) 2 else 1;
        if (out.len < pos.* + idx_len) return error.BufferTooSmall;
        if (wide) {
            std.mem.writeInt(u16, out[pos.*..][0..2], c.index, .little);
        } else out[pos.*] = @intCast(c.index);
        pos.* += idx_len;
        const body = out[pos.*..];
        const written = switch (c.body) {
            .crob => |b| b.encode(body),
            .analog_i32 => |x| (objects.g41.V1{ .value = x }).encode(body),
            .analog_i16 => |x| (objects.g41.V2{ .value = x }).encode(body),
            .analog_f32 => |x| (objects.g41.V3{ .value = x }).encode(body),
            .analog_f64 => |x| (objects.g41.V4{ .value = x }).encode(body),
        } catch return error.BufferTooSmall;
        pos.* += written.len;
    }

    // ── responses ───────────────────────────────────────────────────────────

    /// One received application fragment (a response, or an unsolicited
    /// response). Anything else, a malformed fragment, a response to nothing
    /// we sent and a stale one are ignored. Returns the CONFIRM to send, the
    /// data to read and the task event, each if there is one.
    pub fn handle(self: *Master, fragment: []const u8, now_ms: u64, out: []u8) Error!Handled {
        const d = application.decodeResponseHeader(fragment) catch return .{};
        const rh = d.header;
        switch (rh.function) {
            .unsolicited_response => {
                if (!rh.control.uns) return .{};
                var res: Handled = .{};
                if (rh.control.con) res.confirm = try self.confirm(rh.control.seq, true, out);
                const dup = self.last_uns_seq != null and self.last_uns_seq.? == rh.control.seq;
                self.last_uns_seq = rh.control.seq;
                if (dup) return res;
                self.applyIin(rh.iin, now_ms);
                res.data = .{ .unsolicited = true, .iin = rh.iin, .objects = d.rest, .final = rh.control.fin };
                return res;
            },
            .response => {
                if (self.state != .wait_response) return .{};
                const expected = self.expect_frag_seq orelse self.req_seq;
                if (rh.control.seq != expected) return .{};
                if (self.expect_frag_seq == null and !rh.control.fir) return .{};
                var res: Handled = .{};
                if (rh.control.con) res.confirm = try self.confirm(rh.control.seq, false, out);
                self.applyIin(rh.iin, now_ms);
                switch (self.current) {
                    .command => {},
                    else => res.data = .{ .unsolicited = false, .iin = rh.iin, .objects = d.rest, .final = rh.control.fin },
                }
                if (!rh.control.fin) {
                    self.expect_frag_seq = rh.control.seq +% 1;
                    self.deadline_ms = now_ms + self.cfg.response_timeout_ms;
                    return res;
                }
                self.state = .idle;
                self.expect_frag_seq = null;
                self.retries = 0;
                res.event = self.complete(d.rest, now_ms);
                return res;
            },
            else => return .{},
        }
    }

    fn confirm(self: *Master, seq: u4, uns: bool, out: []u8) Error![]const u8 {
        _ = self;
        const h = application.encodeRequestHeader(
            .{ .control = .{ .fir = true, .fin = true, .uns = uns, .seq = seq }, .function = .confirm },
            out,
        ) catch return error.BufferTooSmall;
        return h;
    }

    /// The task has its complete response: schedule what follows.
    fn complete(self: *Master, body: []const u8, now_ms: u64) ?Event {
        const kind = self.current;
        const i = @backingInt(kind);
        switch (kind) {
            .command => {
                const c = self.cmd.?;
                const status = commandStatus(c, body);
                if (c.select_before_operate and !self.cmd_operate_phase and status == .success) {
                    self.cmd_operate_phase = true; // the OPERATE is built next, keeping `cmd`
                    return null;
                }
                self.cmd = null;
                self.cmd_operate_phase = false;
                return .{ .command_done = .{ .index = c.index, .status = status } };
            },
            .disable_unsolicited => {
                self.due[i] = null;
                self.afterDisable(now_ms);
            },
            .integrity_poll => {
                self.due[i] = if (self.cfg.integrity_poll_ms) |p| now_ms + p else null;
                self.afterIntegrity(now_ms);
            },
            .class_poll_1, .class_poll_2, .class_poll_3 => {
                self.due[i] = if (self.cfg.class_poll_ms[i - @backingInt(TaskKind.class_poll_1)]) |p| now_ms + p else null;
            },
            .delay_measure => {
                self.due[i] = null;
                if (delayFromResponse(body)) |ms| {
                    self.delay_ms = ms;
                    self.schedule(.write_time, now_ms);
                }
            },
            else => self.due[i] = null,
        }
        return .{ .task_done = .{ .kind = kind, .ok = true } };
    }

    /// The outstanding request got no (complete) response in time.
    fn failCurrent(self: *Master, now_ms: u64) ?Event {
        self.state = .idle;
        self.expect_frag_seq = null;
        const kind = self.current;
        const i = @backingInt(kind);
        if (kind == .command) {
            const c = self.cmd.?;
            if (self.retries < self.cfg.max_task_retries) {
                // A command is not retried silently: the outstation may have acted.
            }
            self.cmd = null;
            self.cmd_operate_phase = false;
            self.retries = 0;
            return .{ .command_done = .{ .index = c.index, .status = .timeout } };
        }
        if (self.retries < self.cfg.max_task_retries) {
            self.retries += 1;
            self.due[i] = now_ms + self.cfg.task_retry_ms;
            return null;
        }
        self.retries = 0;
        // A periodic task keeps its schedule; a one-shot is dropped.
        self.due[i] = switch (kind) {
            .integrity_poll => if (self.cfg.integrity_poll_ms) |p| now_ms + p else null,
            .class_poll_1, .class_poll_2, .class_poll_3 => if (self.cfg.class_poll_ms[i - @backingInt(TaskKind.class_poll_1)]) |p| now_ms + p else null,
            else => null,
        };
        if (kind == .disable_unsolicited) self.afterDisable(now_ms);
        return .{ .task_done = .{ .kind = kind, .ok = false } };
    }
};

/// The status the outstation echoed in the response to command `c`.
fn commandStatus(c: Command, body: []const u8) objects.g12.CommandStatus {
    const hd = objects.decodeObjectHeader(body) catch return .format_error;
    const wide = c.index > 0xFF;
    const want_group: u8, const want_var: u8, const obj_len: usize, const status_off: usize = switch (c.body) {
        .crob => .{ 12, 1, 11, 10 },
        .analog_i32 => .{ 41, 1, 5, 4 },
        .analog_i16 => .{ 41, 2, 3, 2 },
        .analog_f32 => .{ 41, 3, 5, 4 },
        .analog_f64 => .{ 41, 4, 9, 8 },
    };
    if (hd.header.group != want_group or hd.header.variation != want_var) return .format_error;
    const idx_len: usize = if (wide) 2 else 1;
    const rest = body[hd.consumed..];
    if (rest.len < idx_len + obj_len) return .format_error;
    return @fromBackingInt(@intCast(rest[idx_len + status_off]));
}

/// g52v2 (time delay fine): count 1, then a 16-bit delay in milliseconds.
fn delayFromResponse(body: []const u8) ?u16 {
    const hd = objects.decodeObjectHeader(body) catch return null;
    if (hd.header.group != 52 or hd.header.variation != 2) return null;
    const rest = body[hd.consumed..];
    if (rest.len < 2) return null;
    return std.mem.readInt(u16, rest[0..2], .little);
}

// ── measurements ────────────────────────────────────────────────────────────

/// Walks the object headers and records of a response body and yields one
/// `Measurement` per point of the groups `records` knows (static and event
/// binary, double-bit binary, binary output, counter, frozen counter, analog
/// input and output). A g51 common time-of-occurrence sets the base of the
/// relative-time events after it; any other object (a g50 time, a g52 delay,
/// an unknown group) ends the walk with `null` and `ok = false`.
pub const Measurements = struct {
    rest: []const u8,
    ok: bool = true,
    cto: ?u64 = null,
    // state of the current object block
    layout: ?records.Layout = null,
    kind: records.PointKind = .binary_input,
    event: bool = false,
    prefix: objects.PrefixCode = .none,
    remaining: u64 = 0,
    next_index: u64 = 0,
    stop_index: u64 = 0,
    packed_pos: usize = 0,
    packed_data: []const u8 = &.{},

    pub fn next(self: *Measurements) ?Measurement {
        while (true) {
            if (self.remaining > 0) {
                if (self.take()) |m| return m;
                if (!self.ok) return null;
                continue;
            }
            if (self.rest.len == 0 or !self.ok) return null;
            const hd = objects.decodeObjectHeader(self.rest) catch {
                self.ok = false;
                return null;
            };
            self.rest = self.rest[hd.consumed..];
            const g = hd.header.group;
            if (g == 51) {
                const n = hd.header.range.objectCount() orelse {
                    self.ok = false;
                    return null;
                };
                if (n == 0) continue;
                if (n * objects.g51.wire_len > self.rest.len) {
                    self.ok = false;
                    return null;
                }
                self.cto = (objects.g51.V1.decode(self.rest) catch unreachable).ms_since_epoch;
                self.rest = self.rest[n * objects.g51.wire_len ..];
                continue;
            }
            const kind_event = if (records.PointKind.fromStaticGroup(g)) |k| .{ k, false } else if (records.PointKind.fromEventGroup(g)) |k| .{ k, true } else {
                self.ok = false;
                return null;
            };
            const layout = records.layoutOf(g, hd.header.variation) orelse {
                self.ok = false;
                return null;
            };
            self.kind = kind_event[0];
            self.event = kind_event[1];
            self.layout = layout;
            self.prefix = hd.header.qualifier.prefix_code;
            switch (hd.header.range) {
                .start_stop => |r| {
                    if (r.stop < r.start) {
                        self.ok = false;
                        return null;
                    }
                    self.next_index = r.start;
                    self.remaining = @as(u64, r.stop) - r.start + 1;
                },
                .count => |c| self.remaining = c,
                .all_values => {
                    self.ok = false;
                    return null;
                },
            }
            self.packed_pos = 0;
            if (layout.isPacked()) {
                const nbytes = if (layout.value == .packed_bit) records.packedBitBytes(@intCast(self.remaining)) else records.packedDoubleBitBytes(@intCast(self.remaining));
                if (nbytes > self.rest.len) {
                    self.ok = false;
                    self.remaining = 0;
                    return null;
                }
                self.packed_data = self.rest[0..nbytes];
                self.rest = self.rest[nbytes..];
            }
        }
    }

    fn take(self: *Measurements) ?Measurement {
        const layout = self.layout.?;
        var index = self.next_index;
        if (layout.isPacked()) {
            const i = self.packed_pos;
            self.packed_pos += 1;
            self.remaining -= 1;
            self.next_index += 1;
            const value: records.Value = if (layout.value == .packed_bit)
                .{ .binary = records.getPackedBit(self.packed_data, i) }
            else
                .{ .double_bit = records.getPackedDoubleBit(self.packed_data, i) };
            return .{ .kind = self.kind, .event = self.event, .index = @intCast(index), .value = value, .flags = .{ .online = true }, .time_ms = null };
        }
        const prefix_len: usize = switch (self.prefix) {
            .none => 0,
            .index_1b => 1,
            .index_2b => 2,
            .index_4b => 4,
            else => {
                self.ok = false;
                self.remaining = 0;
                return null;
            },
        };
        const each = layout.wireLen().? + prefix_len;
        if (self.rest.len < each) {
            self.ok = false;
            self.remaining = 0;
            return null;
        }
        if (prefix_len != 0) index = switch (prefix_len) {
            1 => self.rest[0],
            2 => std.mem.readInt(u16, self.rest[0..2], .little),
            else => std.mem.readInt(u32, self.rest[0..4], .little),
        };
        const rec = records.decode(layout, self.kind, self.rest[prefix_len..]) catch {
            self.ok = false;
            self.remaining = 0;
            return null;
        };
        self.rest = self.rest[each..];
        self.remaining -= 1;
        self.next_index += 1;
        const time: ?u64 = if (rec.time_ms) |t| t else if (rec.time_rel_ms) |r| (if (self.cto) |c| c + r else null) else null;
        return .{ .kind = self.kind, .event = self.event, .index = @intCast(index), .value = rec.value, .flags = rec.flags, .time_ms = time };
    }
};

// ── link + transport framing ────────────────────────────────────────────────

/// A `Master` wrapped in the transport function and the data-link layer: feed
/// it link frames, get link frames back. The counterpart of
/// `outstation.Session`. Requests go out as unconfirmed user data; confirmed
/// user data from the outstation (its `Config.link_confirms`) is ACKed and
/// de-duplicated by the frame-count bit.
pub const Session = struct {
    master: *Master,
    /// This master's link address and the outstation's.
    address: u16,
    outstation_address: u16,
    rx: transport.Reassembler,
    scratch: []u8,
    /// Scratch for one outbound application fragment.
    tx_fragment: []u8,
    tx_seq: u6 = 0,
    rx_link: link_session.Secondary = .{},

    pub const SessionError = Error || link.EncodeError || link.DecodeError || transport.ReassembleError;

    /// What `feedFrame` produced.
    pub const Fed = struct {
        /// Link frames to send (a link ACK, the application CONFIRM), in `out`.
        frames: ?[]u8 = null,
        data: ?Data = null,
        event: ?Event = null,
    };

    pub fn init(master: *Master, address: u16, outstation_address: u16, rx_buf: []u8, scratch: []u8, tx_fragment: []u8) Session {
        return .{
            .master = master,
            .address = address,
            .outstation_address = outstation_address,
            .rx = transport.Reassembler.init(rx_buf),
            .scratch = scratch,
            .tx_fragment = tx_fragment,
        };
    }

    /// The next request as link frames, a timeout event, or nothing.
    pub fn poll(self: *Session, now_ms: u64, out: []u8) SessionError!struct { frames: ?[]u8, event: ?Event } {
        const p = try self.master.poll(now_ms, self.tx_fragment);
        const frames = if (p.request) |req| try self.frame(req, out) else null;
        return .{ .frames = frames, .event = p.event };
    }

    /// One received link frame. Frames not for us, not from the outstation or
    /// not user data are ignored (a link ACK/NACK for a frame we sent as
    /// unconfirmed data does not occur).
    pub fn feedFrame(self: *Session, frame_bytes: []const u8, now_ms: u64, out: []u8) SessionError!Fed {
        const decoded = try link.decodeFrame(frame_bytes, self.scratch);
        if (decoded.dest != self.address or decoded.src != self.outstation_address) return .{};
        const control = decoded.control;
        if (!control.prm) return .{};
        var ack_len: usize = 0;
        switch (self.rx_link.onPrimary(control)) {
            .none => return .{},
            .nack => return .{ .frames = try self.linkReply(.nack, out) },
            .ack_discard => return .{ .frames = try self.linkReply(.ack, out) },
            .deliver => {},
            .ack_deliver => ack_len = (try self.linkReply(.ack, out)).len,
        }
        const fragment = (try self.rx.feed(self.scratch[0..decoded.user_data_len])) orelse return .{ .frames = if (ack_len > 0) out[0..ack_len] else null };
        const h = try self.master.handle(fragment, now_ms, self.tx_fragment);
        var n = ack_len;
        if (h.confirm) |cf| n += (try self.frame(cf, out[n..])).len;
        return .{ .frames = if (n > 0) out[0..n] else null, .data = h.data, .event = h.event };
    }

    fn frame(self: *Session, fragment: []const u8, out: []u8) SessionError![]u8 {
        const control = link.Control{
            .dir = true, // master -> outstation (§9.2.4.1.2)
            .prm = true,
            .function = @backingInt(link.PrimaryFunction.unconfirmed_user_data),
        };
        var seg = transport.Segmenter.init(fragment);
        seg.seq = self.tx_seq;
        var seg_buf: [1 + transport.max_segment_payload]u8 = undefined;
        var pos: usize = 0;
        while (seg.next(&seg_buf)) |segment| {
            const f = try link.encodeFrame(control, self.outstation_address, self.address, segment, out[pos..]);
            pos += f.len;
        }
        self.tx_seq = seg.seq;
        return out[0..pos];
    }

    fn linkReply(self: *Session, function: link.SecondaryFunction, out: []u8) SessionError![]u8 {
        const control = link.Control{ .dir = true, .prm = false, .fcv_or_dfc = false, .function = @backingInt(function) };
        return try link.encodeFrame(control, self.outstation_address, self.address, &.{}, out);
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const outstation = @import("outstation.zig");

/// A small outstation and a master wired back to back.
const Rig = struct {
    binaries: [4]outstation.BinaryInput = undefined,
    dbits: [0]outstation.DoubleBitInput = .{},
    bouts: [2]outstation.BinaryOutputStatus = undefined,
    counters: [2]outstation.Counter = undefined,
    frozen: [0]outstation.FrozenCounter = .{},
    analogs: [3]outstation.AnalogInput = undefined,
    aouts: [1]outstation.AnalogOutputStatus = undefined,
    events: [16]outstation.Event = undefined,
    station: outstation.Outstation = undefined,

    fn setup(self: *Rig, config: outstation.Config) void {
        for (&self.binaries, 0..) |*p, i| p.* = .{ .value = i % 2 == 0, .class = .class1, .static_variation = 2, .event_variation = 2 };
        for (&self.bouts) |*p| p.* = .{ .class = .class1 };
        for (&self.counters, 0..) |*p, i| p.* = .{ .value = @intCast(100 + i), .class = .class3, .static_variation = 1 };
        for (&self.analogs, 0..) |*p, i| p.* = .{ .value = @floatFromInt(i * 5), .class = .class2, .static_variation = 1, .event_variation = 1 };
        for (&self.aouts) |*p| p.* = .{ .class = null, .min = -100, .max = 100 };
        self.station = outstation.Outstation.init(config, .{
            .binary_inputs = &self.binaries,
            .double_bit_inputs = &self.dbits,
            .binary_outputs = &self.bouts,
            .counters = &self.counters,
            .frozen_counters = &self.frozen,
            .analog_inputs = &self.analogs,
            .analog_outputs = &self.aouts,
        }, outstation.EventBuffer.init(&self.events));
    }
};

/// Pump one request through the outstation and its response back into the master.
/// `obuf` holds the response, which `Handled.data` borrows: it must outlive the result.
fn roundTrip(m: *Master, rig: *Rig, request: []const u8, now: u64, mbuf: []u8, obuf: []u8) !?Handled {
    const reply = (try rig.station.handle(request, now, obuf)) orelse return null;
    return try m.handle(reply.fragment, now, mbuf);
}

test "startup: disable unsolicited, integrity poll, enable unsolicited, then idle" {
    var rig = Rig{};
    rig.setup(.{ .unsolicited_supported = true, .need_time_at_start = false });
    var m = Master.init(.{});
    var out: [512]u8 = undefined;
    var out2: [512]u8 = undefined;
    var rbuf: [2048]u8 = undefined;

    const p1 = try m.poll(1000, &out);
    try testing.expectEqual(application.FunctionCode.disable_unsolicited, (try application.decodeRequestHeader(p1.request.?)).header.function);
    try testing.expectEqual(@as(?u64, 6000), m.nextWakeup()); // the response deadline
    // Nothing else goes out while the request is outstanding.
    try testing.expectEqual(@as(?[]const u8, null), (try m.poll(1100, &out2)).request);
    const h1 = (try roundTrip(&m, &rig, p1.request.?, 1100, &out2, &rbuf)).?;
    try testing.expectEqual(TaskKind.disable_unsolicited, h1.event.?.task_done.kind);

    // The outstation reports a restart: the master clears it before anything else.
    try testing.expect(m.iin.device_restart);
    const pc = try m.poll(1150, &out);
    try testing.expectEqual(application.FunctionCode.write, (try application.decodeRequestHeader(pc.request.?)).header.function);
    const hc = (try roundTrip(&m, &rig, pc.request.?, 1150, &out2, &rbuf)).?;
    try testing.expectEqual(TaskKind.clear_restart, hc.event.?.task_done.kind);
    try testing.expect(!m.iin.device_restart);

    const p2 = try m.poll(1200, &out);
    const req2 = try application.decodeRequestHeader(p2.request.?);
    try testing.expectEqual(application.FunctionCode.read, req2.header.function);
    try testing.expectEqual(@as(u4, 2), req2.header.control.seq);
    const h2 = (try roundTrip(&m, &rig, p2.request.?, 1200, &out2, &rbuf)).?;
    try testing.expect(h2.data != null);
    // The integrity data decode into points: 4 binaries, 2 outputs, 2 counters, 3 analogs, ...
    var it = h2.data.?.measurements();
    var n: usize = 0;
    var saw_counter = false;
    while (it.next()) |meas| {
        n += 1;
        if (meas.kind == .counter and meas.index == 1) {
            saw_counter = true;
            try testing.expectEqual(@as(u32, 101), meas.value.counter);
        }
    }
    try testing.expect(it.ok);
    try testing.expect(saw_counter);
    try testing.expectEqual(@as(usize, 4 + 2 + 2 + 3 + 1), n);
    try testing.expectEqual(TaskKind.integrity_poll, h2.event.?.task_done.kind);

    const p3 = try m.poll(1300, &out);
    try testing.expectEqual(application.FunctionCode.enable_unsolicited, (try application.decodeRequestHeader(p3.request.?)).header.function);
    _ = (try roundTrip(&m, &rig, p3.request.?, 1300, &out2, &rbuf)).?;
    try testing.expectEqual(@as(?u64, null), m.nextWakeup());
    try testing.expectEqual(@as(?[]const u8, null), (try m.poll(99_999, &out)).request);
    try testing.expect(rig.station.unsolicited_enabled[0] and rig.station.unsolicited_enabled[2]);
}

fn drive(m: *Master, rig: *Rig, now: u64, mbuf: []u8, obuf: []u8, rbuf: []u8) !?Handled {
    const p = try m.poll(now, mbuf);
    const req = p.request orelse return null;
    return try roundTrip(m, rig, req, now, rbuf, obuf);
}

fn quietCfg() Config {
    return .{ .disable_unsolicited_on_startup = false, .startup_integrity_poll = false, .enable_unsolicited_on_startup = false, .clear_restart_iin = false };
}

test "commands: direct operate and select-before-operate report the outstation's status" {
    var rig = Rig{};
    rig.setup(.{ .need_time_at_start = false });
    var m = Master.init(quietCfg());
    var a: [512]u8 = undefined;
    var b: [2048]u8 = undefined;
    var c: [512]u8 = undefined;

    const crob: objects.g12.V1 = .{ .control_code = .{ .op_type = .latch_on }, .count = 1, .on_time_ms = 100, .off_time_ms = 100 };
    try m.queueCommand(.{ .index = 1, .body = .{ .crob = crob } });
    const h = (try drive(&m, &rig, 100, &a, &b, &c)).?;
    try testing.expectEqual(@as(u16, 1), h.event.?.command_done.index);
    try testing.expectEqual(objects.g12.CommandStatus.success, h.event.?.command_done.status);
    try testing.expect(rig.bouts[1].value);

    // SBO: SELECT and OPERATE are two requests with consecutive sequence numbers.
    try m.queueCommand(.{ .select_before_operate = true, .index = 0, .body = .{ .crob = crob } });
    const p1 = try m.poll(200, &a);
    const r1 = try application.decodeRequestHeader(p1.request.?);
    try testing.expectEqual(application.FunctionCode.select, r1.header.function);
    const h1 = (try roundTrip(&m, &rig, p1.request.?, 200, &c, &b)).?;
    try testing.expect(h1.event == null); // not done yet: the OPERATE follows
    try testing.expect(!rig.bouts[0].value);
    const p2 = try m.poll(210, &a);
    const r2 = try application.decodeRequestHeader(p2.request.?);
    try testing.expectEqual(application.FunctionCode.operate, r2.header.function);
    try testing.expectEqual(r1.header.control.seq +% 1, r2.header.control.seq);
    const h2 = (try roundTrip(&m, &rig, p2.request.?, 210, &c, &b)).?;
    try testing.expectEqual(objects.g12.CommandStatus.success, h2.event.?.command_done.status);
    try testing.expect(rig.bouts[0].value);

    // An analog output outside the point's bounds is refused with its status.
    try m.queueCommand(.{ .index = 0, .body = .{ .analog_f32 = 500 } });
    const h3 = (try drive(&m, &rig, 300, &a, &b, &c)).?;
    try testing.expectEqual(objects.g12.CommandStatus.out_of_range, h3.event.?.command_done.status);
    try m.queueCommand(.{ .index = 0, .body = .{ .analog_i16 = 42 } });
    const h4 = (try drive(&m, &rig, 310, &a, &b, &c)).?;
    try testing.expectEqual(objects.g12.CommandStatus.success, h4.event.?.command_done.status);
    try testing.expectEqual(@as(f64, 42), rig.aouts[0].value);

    // A point index above 255 uses the 2-octet prefix.
    try m.queueCommand(.{ .index = 300, .body = .{ .crob = crob } });
    const h5 = (try drive(&m, &rig, 320, &a, &b, &c)).?;
    try testing.expectEqual(@as(u16, 300), h5.event.?.command_done.index);
    try testing.expect(h5.event.?.command_done.status != .success);
}

test "commands: no response fails the command with timeout, never retried; the queue is bounded" {
    var rig = Rig{};
    rig.setup(.{});
    var m = Master.init(quietCfg());
    var a: [512]u8 = undefined;
    const crob: objects.g12.V1 = .{ .control_code = .{ .op_type = .latch_on }, .count = 1, .on_time_ms = 0, .off_time_ms = 0 };
    try m.queueCommand(.{ .index = 0, .body = .{ .crob = crob } });
    const p = try m.poll(1000, &a);
    try testing.expect(p.request != null);
    try testing.expectEqual(@as(?Event, null), (try m.poll(5999, &a)).event);
    const t = try m.poll(6000, &a);
    try testing.expectEqual(objects.g12.CommandStatus.timeout, t.event.?.command_done.status);
    try testing.expectEqual(@as(?u64, null), m.nextWakeup());
    for (0..cmd_queue_len) |_| try m.queueCommand(.{ .index = 0, .body = .{ .crob = crob } });
    try testing.expectError(error.QueueFull, m.queueCommand(.{ .index = 0, .body = .{ .crob = crob } }));
}

test "a poll that gets no answer is retried after task_retry_ms and dropped after max_task_retries" {
    var rig = Rig{};
    rig.setup(.{});
    var cfg = quietCfg();
    cfg.max_task_retries = 1;
    cfg.response_timeout_ms = 100;
    cfg.task_retry_ms = 50;
    var m = Master.init(cfg);
    var a: [512]u8 = undefined;
    m.classPoll(2, 0);
    try testing.expect((try m.poll(0, &a)).request != null);
    try testing.expectEqual(@as(?Event, null), (try m.poll(100, &a)).event); // first failure: retry scheduled
    try testing.expectEqual(@as(?u64, 150), m.nextWakeup());
    try testing.expectEqual(@as(?[]const u8, null), (try m.poll(149, &a)).request);
    try testing.expect((try m.poll(150, &a)).request != null);
    const gone = try m.poll(250, &a);
    try testing.expect(!gone.event.?.task_done.ok);
    try testing.expectEqual(TaskKind.class_poll_2, gone.event.?.task_done.kind);
    try testing.expectEqual(@as(?u64, null), m.nextWakeup());
}

test "a response that is stale, foreign or out of sequence is ignored" {
    var rig = Rig{};
    rig.setup(.{ .need_time_at_start = false });
    var m = Master.init(quietCfg());
    var a: [512]u8 = undefined;
    var b: [512]u8 = undefined;
    var c: [512]u8 = undefined;
    // Nothing outstanding: a response is dropped.
    const stray = [_]u8{ 0xC0, 0x81, 0, 0 };
    try testing.expect((try m.handle(&stray, 0, &c)).event == null);
    m.classPoll(1, 0);
    const p = try m.poll(10, &a);
    const seq = (try application.decodeRequestHeader(p.request.?)).header.control.seq;
    var wrong = [_]u8{ 0xC0 | @as(u8, seq +% 1), 0x81, 0, 0 };
    const hw = try m.handle(&wrong, 20, &c);
    try testing.expect(hw.event == null and hw.data == null);
    try testing.expect(m.state == .wait_response);
    // Garbage and a request-shaped fragment are ignored.
    try testing.expect((try m.handle(&.{0xC0}, 20, &c)).data == null);
    try testing.expect((try m.handle(&.{ 0xC0, 0x01 }, 20, &c)).data == null);
    // The right one completes it.
    const hok = (try roundTrip(&m, &rig, p.request.?, 30, &c, &b)).?;
    try testing.expectEqual(TaskKind.class_poll_1, hok.event.?.task_done.kind);
}

test "IIN class bits trigger class polls whose events decode with their times; the poll CONFIRMs" {
    var rig = Rig{};
    rig.setup(.{ .need_time_at_start = false });
    var cfg = quietCfg();
    cfg.class_poll_ms = .{ null, null, null };
    var m = Master.init(cfg);
    var a: [512]u8 = undefined;
    var b: [2048]u8 = undefined;
    var c: [512]u8 = undefined;
    rig.station.update(.binary_input, 2, .{ .binary = false }, 1_700_000_000_000);
    // Any response carries IIN1.1 now; a delay-free way to get one is an integrity poll.
    m.integrityPoll(0);
    _ = (try drive(&m, &rig, 5, &a, &b, &c)).?;
    try testing.expect(m.iin.class_1_events);
    // The IIN scheduled the class 1 poll.
    const p = try m.poll(6, &a);
    try testing.expectEqual(application.FunctionCode.read, (try application.decodeRequestHeader(p.request.?)).header.function);
    const h = (try roundTrip(&m, &rig, p.request.?, 6, &c, &b)).?;
    try testing.expect(h.confirm != null); // events: CON set, master confirms
    const cf = try application.decodeRequestHeader(h.confirm.?);
    try testing.expectEqual(application.FunctionCode.confirm, cf.header.function);
    try testing.expect(!cf.header.control.uns);
    var it = h.data.?.measurements();
    const ev = it.next().?;
    try testing.expect(ev.event and ev.kind == .binary_input and ev.index == 2);
    try testing.expectEqual(@as(?u64, 1_700_000_000_000), ev.time_ms);
    try testing.expect(it.next() == null and it.ok);
    // The confirm retires the events on the outstation.
    try testing.expectEqual(@as(?outstation.Reply, null), try rig.station.handle(h.confirm.?, 7, &b));
    try testing.expect(rig.station.events.isEmpty());
}

test "unsolicited responses are CONFIRMed with the UNS bit; a repeat of the same sequence is confirmed but not delivered twice" {
    var rig = Rig{};
    rig.setup(.{ .unsolicited_supported = true, .unsolicited_enabled_at_start = true, .need_time_at_start = false });
    var m = Master.init(quietCfg());
    var out: [2048]u8 = undefined;
    var c: [512]u8 = undefined;
    // Clear the restart IIN the way a master does, or the outstation will not report.
    rig.station.restart = false;
    rig.station.update(.analog_input, 1, .{ .analog_int = 77 }, 4000);
    const reply = (try rig.station.unsolicited(5000, &out)).?;
    const h = try m.handle(reply.fragment, 5000, &c);
    try testing.expect(h.data.?.unsolicited);
    var it = h.data.?.measurements();
    const ev = it.next().?;
    try testing.expect(ev.kind == .analog_input and ev.index == 1);
    const cf = try application.decodeRequestHeader(h.confirm.?);
    try testing.expect(cf.header.control.uns);
    try testing.expectEqual((try application.decodeResponseHeader(reply.fragment)).header.control.seq, cf.header.control.seq);
    // The same fragment again (the confirm was lost and the outstation retried).
    const again = try m.handle(reply.fragment, 6000, &c);
    try testing.expect(again.confirm != null and again.data == null);
    // The master's confirm releases the outstation.
    try testing.expectEqual(@as(?outstation.Reply, null), try rig.station.handle(h.confirm.?, 6100, &out));
    try testing.expect(rig.station.events.isEmpty());
}

test "time sync: NEED_TIME writes the clock (LAN), or measures the delay first (non-LAN) and adds half of it" {
    {
        var rig = Rig{};
        rig.setup(.{});
        var cfg = quietCfg();
        cfg.time_sync = .lan;
        var m = Master.init(cfg);
        var a: [512]u8 = undefined;
        var b: [2048]u8 = undefined;
        var c: [512]u8 = undefined;
        m.integrityPoll(0);
        _ = (try drive(&m, &rig, 0, &a, &b, &c)).?;
        try testing.expect(m.iin.need_time);
        const p = try m.poll(10, &a);
        const body = (try application.decodeRequestHeader(p.request.?)).rest;
        try testing.expectEqual(@as(u8, 50), body[0]);
        try testing.expectEqual(@as(u48, 10), std.mem.readInt(u48, body[4..10], .little));
        const h = (try roundTrip(&m, &rig, p.request.?, 10, &c, &b)).?;
        try testing.expectEqual(TaskKind.write_time, h.event.?.task_done.kind);
        try testing.expect(!m.iin.need_time);
    }
    {
        var rig = Rig{};
        rig.setup(.{ .delay_measure_ms = 40 });
        var cfg = quietCfg();
        cfg.time_sync = .non_lan;
        var m = Master.init(cfg);
        var a: [512]u8 = undefined;
        var b: [2048]u8 = undefined;
        var c: [512]u8 = undefined;
        m.integrityPoll(0);
        _ = (try drive(&m, &rig, 0, &a, &b, &c)).?;
        const pd = try m.poll(10, &a);
        try testing.expectEqual(application.FunctionCode.delay_measure, (try application.decodeRequestHeader(pd.request.?)).header.function);
        const hd = (try roundTrip(&m, &rig, pd.request.?, 10, &c, &b)).?;
        try testing.expectEqual(TaskKind.delay_measure, hd.event.?.task_done.kind);
        try testing.expectEqual(@as(u16, 40), m.delay_ms);
        const pw = try m.poll(20, &a);
        const body = (try application.decodeRequestHeader(pw.request.?)).rest;
        try testing.expectEqual(@as(u48, 20 + 20), std.mem.readInt(u48, body[4..10], .little));
    }
}

test "a multi-fragment response is CONFIRMed per fragment and its measurements all decode" {
    var rig = Rig{};
    rig.setup(.{ .max_tx_fragment = 36, .need_time_at_start = false });
    var m = Master.init(quietCfg());
    var a: [512]u8 = undefined;
    var b: [2048]u8 = undefined;
    var c: [512]u8 = undefined;
    m.integrityPoll(0);
    const p = try m.poll(0, &a);
    var reply = (try rig.station.handle(p.request.?, 0, &b)).?;
    var total: usize = 0;
    var fragments: usize = 0;
    while (true) {
        const h = try m.handle(reply.fragment, 1, &c);
        fragments += 1;
        var it = h.data.?.measurements();
        while (it.next()) |_| total += 1;
        try testing.expect(it.ok);
        if (h.event != null) {
            try testing.expectEqual(TaskKind.integrity_poll, h.event.?.task_done.kind);
            try testing.expect(!reply.more);
            break;
        }
        try testing.expect(reply.more and h.confirm != null);
        try testing.expectEqual(@as(?outstation.Reply, null), try rig.station.handle(h.confirm.?, 1, &b));
        reply = (try rig.station.next(1, &b)).?;
    }
    try testing.expect(fragments > 1);
    try testing.expectEqual(@as(usize, 4 + 2 + 2 + 3 + 1), total);
    try testing.expect(m.state == .idle);
}

test "Measurements: relative times resolve against the g51 common time; an unknown object ends the walk" {
    // g51v1 at t=5000; g2v3 indices 3, 4 with offsets 0x0010 and 0x0200 (flags 0x81 = online, value on).
    const body = [_]u8{ 51, 1, 0x07, 1, 0x88, 0x13, 0, 0, 0, 0 } ++
        [_]u8{ 2, 3, 0x17, 2, 3, 0x81, 0x10, 0x00, 4, 0x01, 0x00, 0x02 } ++
        [_]u8{ 99, 1, 0x07, 1, 0 };
    var it: Measurements = .{ .rest = &body };
    const a = it.next().?;
    try testing.expectEqual(@as(u32, 3), a.index);
    try testing.expectEqual(@as(?u64, 5016), a.time_ms);
    try testing.expect(a.value.binary);
    const b = it.next().?;
    try testing.expectEqual(@as(?u64, 5512), b.time_ms);
    try testing.expect(!b.value.binary);
    try testing.expect(it.next() == null);
    try testing.expect(!it.ok);
    // Truncated records end the walk, not the program.
    const cut = [_]u8{ 30, 1, 0x00, 0, 1, 0x01, 1, 0, 0 }; // two g30v1 records needed, 3 bytes present
    var it2: Measurements = .{ .rest = &cut };
    try testing.expect(it2.next() == null and !it2.ok);
}

test "Session: a master and an outstation Session talk over link frames: startup, a poll with events, a command" {
    var rig = Rig{};
    rig.setup(.{ .address = 10, .master_address = 1, .need_time_at_start = false });
    var m = Master.init(.{ .clear_restart_iin = true });
    var mrx: [2048]u8 = undefined;
    var mscratch: [512]u8 = undefined;
    var mtx: [2048]u8 = undefined;
    var ms = Session.init(&m, 1, 10, &mrx, &mscratch, &mtx);
    var orx: [2048]u8 = undefined;
    var oscratch: [512]u8 = undefined;
    var otx: [2048]u8 = undefined;
    var os = outstation.Session.init(&rig.station, &orx, &oscratch, &otx);
    var wire_m: [2048]u8 = undefined;
    var wire_o: [2048]u8 = undefined;
    var wire_c: [512]u8 = undefined;

    // Run the master until it has nothing more to send, shuttling frames both ways.
    var now: u64 = 1000;
    var done_tasks: usize = 0;
    var spins: usize = 0;
    while (spins < 40) : (spins += 1) {
        now += 10;
        const p = try ms.poll(now, &wire_m);
        const frames = p.frames orelse break;
        const reply = (try os.feedFrame(frames, now, &wire_o)) orelse continue;
        var off: usize = 0;
        while (off < reply.len) {
            const flen = link.maxFrameLen(reply[off + 2] - 5);
            const fed = try ms.feedFrame(reply[off..][0..flen], now, &wire_c);
            if (fed.event) |ev| switch (ev) {
                .task_done => done_tasks += 1,
                else => {},
            };
            off += flen;
        }
    }
    try testing.expect(done_tasks >= 3); // disable unsolicited, clear restart, integrity poll (+ enable)
    try testing.expect(m.iin.device_restart == false);
}
