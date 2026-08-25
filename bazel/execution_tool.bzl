"""Expose a test tool built for the execution platform through runfiles."""

def _execution_tool_impl(ctx):
    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(
        output = executable,
        target_file = ctx.executable.tool,
        is_executable = True,
    )
    tool = ctx.attr.tool[DefaultInfo]
    return DefaultInfo(
        executable = executable,
        runfiles = ctx.runfiles().merge(tool.default_runfiles).merge(tool.data_runfiles),
    )

execution_tool = rule(
    implementation = _execution_tool_impl,
    attrs = {
        "tool": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
        ),
    },
    executable = True,
)
