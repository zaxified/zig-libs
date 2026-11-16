// SPDX-License-Identifier: MIT
//! The standard `grpc.health.v1.Health` service (`Check` and `Watch`), per the
//! public gRPC health-checking protocol (`grpc.health.v1`). Kubernetes gRPC
//! probes and most gRPC load balancers speak exactly this.
//!
//! ```zig
//! var health = grpc.Health.init(io, gpa);
//! defer health.deinit();
//! try health.set("echo.Echo", .serving);
//! // The handlers find the registry through `Router.context`:
//! var router: grpc.Router = .{ .gpa = gpa, .context = &health, .services = &.{
//!     grpc.health.service_from_context, echo_service,
//! } };
//! ```
//!
//! Semantics (from the protocol document):
//!   * service name `""` is the overall server status; it starts `SERVING`;
//!   * `Check` of a registered service answers its status; of an unregistered
//!     one it fails `NOT_FOUND`;
//!   * `Watch` sends the current status first (`SERVICE_UNKNOWN` for an
//!     unregistered service, not an error), then one message per change.
//!
//! A `Watch` handler blocks its call on a condition variable and wakes once a
//! second to honour the call's deadline. It ends when the deadline expires, the
//! client's stream breaks (the next send fails), or `Health.shutdown` is called
//! (every status becomes `NOT_SERVING`, watchers are told, then finish with OK).
//! A client that disconnects while the status is stable is noticed only at the
//! next change or deadline: no write happens in between.

const std = @import("std");
const protobuf = @import("protobuf");
const server = @import("server.zig");

const Allocator = std.mem.Allocator;

/// `HealthCheckResponse.ServingStatus`. Open (non-exhaustive), like every
/// proto3 enum.
pub const ServingStatus = enum(i32) {
    unknown = 0,
    serving = 1,
    not_serving = 2,
    service_unknown = 3,
    _,
};

/// `grpc.health.v1.HealthCheckRequest`.
pub const HealthCheckRequest = struct {
    service: []const u8 = "",
    pub const pb_fields = .{
        .service = protobuf.Field{ .number = 1, .kind = .string },
    };
};

/// `grpc.health.v1.HealthCheckResponse`.
pub const HealthCheckResponse = struct {
    status: ServingStatus = .unknown,
    pub const pb_fields = .{
        .status = protobuf.Field{ .number = 1, .kind = .@"enum" },
    };
};

/// The status registry the application owns and updates. Thread-safe: any
/// thread may `set`/`remove` while handlers read.
pub const Health = struct {
    io: std.Io,
    gpa: Allocator,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    /// Status of `""`, the overall server.
    overall: ServingStatus = .serving,
    /// Named services; keys are owned.
    map: std.StringHashMapUnmanaged(ServingStatus) = .empty,
    shutting_down: bool = false,
    /// Count of watch messages delivered (diagnostics and tests).
    delivered: u64 = 0,

    pub fn init(io: std.Io, gpa: Allocator) Health {
        return .{ .io = io, .gpa = gpa };
    }

    pub fn deinit(h: *Health) void {
        var it = h.map.keyIterator();
        while (it.next()) |k| h.gpa.free(k.*);
        h.map.deinit(h.gpa);
    }

    /// Set the status of `service` (`""` = overall). Registers it if new.
    /// Wakes every `Watch`. After `shutdown` this is a no-op (the server is
    /// going away; a late `set(.serving)` must not resurrect it).
    pub fn set(h: *Health, service: []const u8, status: ServingStatus) Allocator.Error!void {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        if (h.shutting_down) return;
        if (service.len == 0) {
            h.overall = status;
        } else if (h.map.getPtr(service)) |p| {
            p.* = status;
        } else {
            const key = try h.gpa.dupe(u8, service);
            h.map.put(h.gpa, key, status) catch |e| {
                h.gpa.free(key);
                return e;
            };
        }
        h.cond.broadcast(h.io);
    }

    /// Unregister `service`: `Check` then answers `NOT_FOUND` and watchers see
    /// `SERVICE_UNKNOWN`. `""` cannot be removed; it is reset to `SERVING`.
    pub fn remove(h: *Health, service: []const u8) void {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        if (h.shutting_down) return;
        if (service.len == 0) {
            h.overall = .serving;
        } else if (h.map.fetchRemove(service)) |kv| {
            h.gpa.free(kv.key);
        }
        h.cond.broadcast(h.io);
    }

    /// Every status becomes `NOT_SERVING` and stays so; open `Watch` calls
    /// deliver that and then complete. Call it first thing on server shutdown.
    pub fn shutdown(h: *Health) void {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        h.overall = .not_serving;
        var it = h.map.valueIterator();
        while (it.next()) |v| v.* = .not_serving;
        h.shutting_down = true;
        h.cond.broadcast(h.io);
    }

    /// Current status of `service`, null when it is not registered.
    pub fn get(h: *Health, service: []const u8) ?ServingStatus {
        h.mutex.lockUncancelable(h.io);
        defer h.mutex.unlock(h.io);
        return h.lookupLocked(service);
    }

    fn lookupLocked(h: *Health, service: []const u8) ?ServingStatus {
        if (service.len == 0) return h.overall;
        return h.map.get(service);
    }
};

const M = server.Methods(HealthCheckRequest, HealthCheckResponse);

/// The `grpc.health.v1.Health` service, with `get` telling the handlers which
/// registry to use for a given call (so the registry need not be
/// `Router.context`).
pub fn Service(comptime get: fn (*server.Call) *Health) server.Service {
    const Impl = struct {
        fn check(c: *server.Call, req: HealthCheckRequest) anyerror!HealthCheckResponse {
            const status = get(c).get(req.service) orelse
                return c.fail(.not_found, "unknown service");
            return .{ .status = status };
        }

        fn watch(s: *M.Stream, req: HealthCheckRequest) anyerror!void {
            const h = get(s.call);
            var last: ?ServingStatus = null;
            while (true) {
                var cur: ServingStatus = undefined;
                var done = false;
                h.mutex.lockUncancelable(h.io);
                while (true) {
                    cur = h.lookupLocked(req.service) orelse .service_unknown;
                    done = h.shutting_down;
                    if (last == null or last.? != cur or done) break;
                    h.cond.waitTimeout(h.io, &h.mutex, .{ .duration = .{
                        .raw = .fromMilliseconds(1000),
                        .clock = .awake,
                    } }) catch |e| switch (e) {
                        error.Timeout => {
                            if (s.call.expired()) break;
                        },
                        error.Canceled => {
                            h.mutex.unlock(h.io);
                            return s.call.fail(.cancelled, "watch canceled");
                        },
                    };
                }
                h.mutex.unlock(h.io);

                if (last == null or last.? != cur) {
                    try s.send(.{ .status = cur });
                    last = cur;
                    h.mutex.lockUncancelable(h.io);
                    h.delivered += 1;
                    h.mutex.unlock(h.io);
                }
                if (done) return;
                if (s.call.expired()) return s.call.fail(.deadline_exceeded, "context deadline exceeded");
            }
        }
    };
    return .{
        .name = "grpc.health.v1.Health",
        .methods = &.{
            M.unary("Check", Impl.check),
            M.serverStreaming("Watch", Impl.watch),
        },
    };
}

fn contextHealth(c: *server.Call) *Health {
    return @ptrCast(@alignCast(c.context().?));
}

/// The service reading its registry from `Router.context` (which must then be
/// the `*Health`).
pub const service_from_context: server.Service = Service(contextHealth);
