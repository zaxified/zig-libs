const std = @import("std");

// A consumer's build.zig, written the way a consumer writes one: zig-libs is a
// package dependency, and every module this binary needs is taken from it by
// name. Nothing here reaches into the collection's own build — that is the
// point of this directory.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // ReleaseSafe by default. Every safety check stays on, which is what you
    // want from a network-facing binary; `-Doptimize=ReleaseFast` if you have
    // measured that you need it.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const zig_libs = b.dependency("zig_libs", .{ .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{
        .name = "http-service",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "http", .module = zig_libs.module("http") },
                .{ .name = "router", .module = zig_libs.module("router") },
                .{ .name = "cors", .module = zig_libs.module("cors") },
                .{ .name = "security-headers", .module = zig_libs.module("security-headers") },
                .{ .name = "ratelimit", .module = zig_libs.module("ratelimit") },
                .{ .name = "requestid", .module = zig_libs.module("requestid") },
                .{ .name = "health", .module = zig_libs.module("health") },
                .{ .name = "throttle", .module = zig_libs.module("throttle") },
                .{ .name = "abuseguard", .module = zig_libs.module("abuseguard") },
                .{ .name = "aaa-gate", .module = zig_libs.module("aaa-gate") },
                .{ .name = "idempotency", .module = zig_libs.module("idempotency") },
                .{ .name = "tracecontext", .module = zig_libs.module("tracecontext") },
                .{ .name = "webhooksig", .module = zig_libs.module("webhooksig") },
                .{ .name = "openapi", .module = zig_libs.module("openapi") },
                .{ .name = "ramcache", .module = zig_libs.module("ramcache") },
                .{ .name = "accesslog", .module = zig_libs.module("accesslog") },
                .{ .name = "netaddr", .module = zig_libs.module("netaddr") },
            },
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Build and run (pass options after --, e.g. -- --port 8087)").dependOn(&run.step);
}
