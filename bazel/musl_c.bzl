"""Runs a test on the musl platform that also selects the LLVM musl C library.

The repository's musl platforms keep the LLVM C toolchain's default libc, so
Rust executables link as static PIE with Rust's own musl objects. The Go and
Python binding tests compile or link C code for musl, so on a musl lane they
build for `//platforms:linux_<cpu>_musl_c` instead. On other platforms the
wrapper is incompatible and the wrapped test runs directly.
"""

_MUSL_C_PLATFORMS = {
    "//platforms:linux_aarch64_musl": "//platforms:linux_aarch64_musl_c",
    "//platforms:linux_x86_64_musl": "//platforms:linux_x86_64_musl_c",
}

def _musl_c_transition_impl(settings, _attr):
    platforms = settings["//command_line_option:platforms"]
    if len(platforms) == 1:
        current = str(platforms[0])
        for musl, musl_c in _MUSL_C_PLATFORMS.items():
            if current.endswith(musl):
                return {"//command_line_option:platforms": musl_c}
    return {"//command_line_option:platforms": [str(platform) for platform in platforms]}

_musl_c_transition = transition(
    implementation = _musl_c_transition_impl,
    inputs = ["//command_line_option:platforms"],
    outputs = ["//command_line_option:platforms"],
)

def _musl_c_test_impl(ctx):
    test = ctx.attr.test[0]
    default = test[DefaultInfo]
    executable = default.files_to_run.executable
    output = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(output = output, target_file = executable, is_executable = True)
    providers = [DefaultInfo(
        executable = output,
        runfiles = ctx.runfiles(files = [output]).merge(default.default_runfiles),
    )]
    if RunEnvironmentInfo in test:
        providers.append(test[RunEnvironmentInfo])
    return providers

musl_c_test = rule(
    implementation = _musl_c_test_impl,
    attrs = {
        "test": attr.label(
            cfg = _musl_c_transition,
            executable = True,
            mandatory = True,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
    test = True,
)
