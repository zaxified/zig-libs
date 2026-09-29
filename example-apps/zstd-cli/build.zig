const std = @import("std");

// A consumer's build.zig, written the way a consumer writes one: zig-libs is a
// package dependency, and the zstd module is taken from it by name.
pub fn build(b: *std.Build) void {
    // LLVM unless -Dselfhosted: the self-hosted backend is for the edit loop only.
    const selfhosted = b.option(bool, "selfhosted", "Use Zig's self-hosted backend in Debug (edit loop only)") orelse false;
    const use_llvm: ?bool = if (selfhosted) null else true;
    const target = b.standardTargetOptions(.{});
    // ReleaseFast by default: this is a compression tool, and the byte-exact
    // frames do not depend on the mode. `-Doptimize=ReleaseSafe` keeps every
    // safety check (and turns on the leak check at exit).
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size (default: ReleaseFast)",
    ) orelse .ReleaseFast;

    const zig_libs = b.dependency("zig_libs", .{ .target = target, .optimize = optimize });
    const zstd = zig_libs.module("zstd");

    const exe = b.addExecutable(.{
        .use_llvm = use_llvm,
        .name = "zstd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zstd", .module = zstd }},
        }),
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Build and run (pass args after --, e.g. -- -19 file)").dependOn(&run.step);

    const tests = b.addTest(.{
        .use_llvm = use_llvm,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zstd", .module = zstd }},
        }),
    });
    b.step("test", "Run the unit tests").dependOn(&b.addRunArtifact(tests).step);
}
