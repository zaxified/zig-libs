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
    //
    // ⚠ NOT `standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe })`,
    // which is what this was and which does neither of the two things the
    // sentence above promises. Read std's implementation: given a preferred
    // mode it registers `-Drelease=[bool]` and NOT `-Doptimize` at all, and
    // with no flag it returns `.Debug` — so every build of this app was a Debug
    // build, and the documented `-Doptimize=ReleaseFast` was rejected as an
    // invalid option. Found by trying to build the app in a second optimize
    // mode for the smoke gate.
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (default: ReleaseSafe)",
    ) orelse .ReleaseSafe;

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
                .{ .name = "metrics", .module = zig_libs.module("metrics") },
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
