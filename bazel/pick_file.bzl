"""Copies the one file of a target that has a given extension to a new path.

A shared library target on Windows also outputs an import library and debug
information; packaging needs only the DLL.
"""

def _pick_file_impl(ctx):
    matches = [
        file
        for file in ctx.attr.src[DefaultInfo].files.to_list()
        if file.basename.endswith(ctx.attr.extension)
    ]
    if len(matches) != 1:
        fail("{} has {} files ending in {}, expected one".format(
            ctx.attr.src.label,
            len(matches),
            ctx.attr.extension,
        ))
    output = ctx.actions.declare_file(ctx.attr.out)
    ctx.actions.symlink(output = output, target_file = matches[0])
    return [DefaultInfo(files = depset([output]))]

pick_file = rule(
    implementation = _pick_file_impl,
    attrs = {
        "extension": attr.string(mandatory = True),
        "out": attr.string(mandatory = True),
        "src": attr.label(mandatory = True),
    },
)
