const std = @import("std");

// A consumer's build.zig, written the way a consumer writes one: zig-libs is a
// package dependency, and every module this binary needs is taken from it by
// name. Nothing here reaches into the collection's own build — that is the
// point of this directory.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // ReleaseSafe by default; see raft-kv's build.zig for why this is not
    // `standardOptimizeOption(.{ .preferred_optimize_mode = .safe })`.
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (default: ReleaseSafe)",
    ) orelse .safe;

    const zig_libs = b.dependency("zig_libs", .{ .target = target, .optimize = optimize });
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "traceroute", .module = zig_libs.module("traceroute") },
        .{ .name = "dns", .module = zig_libs.module("dns") },
        .{ .name = "netaddr", .module = zig_libs.module("netaddr") },
    };

    const exe = b.addExecutable(.{
        // `dns` reaches the crypto modules' inline asm, which only LLVM assembles.
        .use_llvm = true,
        .name = "tiny-mtr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = imports,
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    run.addPassthruArgs();
    b.step("run", "Build and run (pass args after --, e.g. -- example.net)").dependOn(&run.step);

    const tests = b.addTest(.{
        // `dns` reaches the crypto modules' inline asm, which only LLVM assembles.
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = imports,
        }),
    });
    b.step("test", "Run the unit tests").dependOn(&b.addRunArtifact(tests).step);
}
