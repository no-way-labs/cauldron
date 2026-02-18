const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build mitt app
    const mitt_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/mitt/src/main.zig"),
    });

    const mitt_exe = b.addExecutable(.{
        .name = "mitt",
        .root_module = mitt_module,
    });
    b.installArtifact(mitt_exe);

    // Run step for mitt
    const mitt_run = b.addRunArtifact(mitt_exe);
    mitt_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        mitt_run.addArgs(args);
    }
    const mitt_run_step = b.step("mitt", "Run the mitt app");
    mitt_run_step.dependOn(&mitt_run.step);

    // Default run step (runs mitt)
    const run_step = b.step("run", "Run the default app (mitt)");
    run_step.dependOn(&mitt_run.step);

    // Unit tests for mitt
    const mitt_test_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/mitt/src/main.zig"),
    });

    const mitt_tests = b.addTest(.{
        .root_module = mitt_test_module,
    });
    const run_mitt_tests = b.addRunArtifact(mitt_tests);

    // Integration tests for mitt
    const integration_test_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/mitt/src/test_integration.zig"),
    });

    const integration_tests = b.addTest(.{
        .root_module = integration_test_module,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    // Shared familiar core module (used by both seance and familiar)
    const familiar_core = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/familiar/src/core.zig"),
    });

    // Build seance app
    const seance_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/seance/src/main.zig"),
    });
    seance_module.addImport("familiar_core", familiar_core);

    const seance_exe = b.addExecutable(.{
        .name = "seance",
        .root_module = seance_module,
    });
    b.installArtifact(seance_exe);

    // Run step for seance
    const seance_run = b.addRunArtifact(seance_exe);
    seance_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        seance_run.addArgs(args);
    }
    const seance_run_step = b.step("seance", "Run the seance app");
    seance_run_step.dependOn(&seance_run.step);

    // Unit tests for seance
    const seance_test_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/seance/src/main.zig"),
    });
    seance_test_module.addImport("familiar_core", familiar_core);

    const seance_tests = b.addTest(.{
        .root_module = seance_test_module,
    });
    const run_seance_tests = b.addRunArtifact(seance_tests);

    // Build familiar app
    const familiar_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/familiar/src/main.zig"),
    });
    familiar_module.addImport("familiar_core", familiar_core);

    const familiar_exe = b.addExecutable(.{
        .name = "familiar",
        .root_module = familiar_module,
    });
    b.installArtifact(familiar_exe);

    // Run step for familiar
    const familiar_run = b.addRunArtifact(familiar_exe);
    familiar_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        familiar_run.addArgs(args);
    }
    const familiar_run_step = b.step("familiar", "Run the familiar app");
    familiar_run_step.dependOn(&familiar_run.step);

    // Unit tests for familiar
    const familiar_test_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/familiar/src/main.zig"),
    });
    familiar_test_module.addImport("familiar_core", familiar_core);

    const familiar_tests = b.addTest(.{
        .root_module = familiar_test_module,
    });
    const run_familiar_tests = b.addRunArtifact(familiar_tests);

    // Build omen app
    const omen_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/omen/src/main.zig"),
    });

    const omen_exe = b.addExecutable(.{
        .name = "omen",
        .root_module = omen_module,
    });
    b.installArtifact(omen_exe);

    // Run step for omen
    const omen_run = b.addRunArtifact(omen_exe);
    omen_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        omen_run.addArgs(args);
    }
    const omen_run_step = b.step("omen", "Run the omen app");
    omen_run_step.dependOn(&omen_run.step);

    // Unit tests for omen
    const omen_test_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("apps/omen/src/main.zig"),
    });

    const omen_tests = b.addTest(.{
        .root_module = omen_test_module,
    });
    const run_omen_tests = b.addRunArtifact(omen_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mitt_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_seance_tests.step);
    test_step.dependOn(&run_familiar_tests.step);
    test_step.dependOn(&run_omen_tests.step);
}
