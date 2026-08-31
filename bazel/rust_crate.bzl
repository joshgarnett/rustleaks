load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load(
    "@rules_rust//rust:defs.bzl",
    "rust_doc",
    "rust_doc_test",
    "rust_library",
    "rust_test",
)

_DOC_TEST_INCOMPATIBLE = select({
    "@platforms//os:windows": ["@platforms//:incompatible"],
    # rules_rust 0.72.0's stable-channel doctest writer strips every path
    # separator when musl's LLVM link inputs contribute an empty artifact
    # root. The authoritative GNU gate still runs every doctest.
    "//platforms:musl": ["@platforms//:incompatible"],
    "//conditions:default": [],
})

def rustleaks_build_contract_files():
    """Exports a crate's complete checked-in Cargo/Bazel contract to its audit test."""
    native.filegroup(
        name = "build_contract_files",
        srcs = native.glob(["**"]),
        visibility = ["//visibility:public"],
    )

def rustleaks_library(
        name,
        crate_name,
        edition,
        version,
        aliases_extra = {},
        crate_features = [],
        deps = [],
        compile_data = [],
        data = [],
        srcs = None,
        unit_test = True,
        unit_test_tags = [],
        docs = True,
        visibility = ["//visibility:public"]):
    """Defines a first-party library and its Cargo-equivalent unit/doc targets."""
    if srcs == None:
        srcs = native.glob(["src/**/*.rs"])

    rustc_env = {
        "CARGO_MANIFEST_DIR": native.package_name(),
        "CARGO_PKG_NAME": crate_name.replace("_", "-"),
        "CARGO_PKG_VERSION": version,
    }

    rust_library(
        name = name,
        aliases = aliases() | aliases_extra,
        compile_data = compile_data,
        crate_features = crate_features,
        crate_name = crate_name,
        data = data,
        deps = all_crate_deps(normal = True) + deps,
        edition = edition,
        rustc_env = rustc_env,
        srcs = srcs,
        visibility = visibility,
    )

    if unit_test:
        rust_test(
            name = name + "_unit_test",
            aliases = aliases(normal = True, normal_dev = True) | aliases_extra,
            crate = ":" + name,
            crate_features = crate_features,
            data = data,
            deps = all_crate_deps(normal = True, normal_dev = True) + deps,
            rustc_env = rustc_env,
            tags = unit_test_tags,
            visibility = visibility,
        )

    if docs:
        rust_doc(
            name = name + "_docs",
            crate = ":" + name,
            rustdoc_flags = ["-Dwarnings"],
            visibility = visibility,
        )
        rust_doc_test(
            name = name + "_doc_test",
            crate = ":" + name,
            deps = [
                "//bazel:compiler_rt_builtins",
                "//bazel:llvm_unwind",
            ],
            proc_macro_deps = ["//bazel:doctest_path_mapper"],
            rustdoc_flags = ["-Dwarnings"],
            target_compatible_with = _DOC_TEST_INCOMPATIBLE,
            visibility = visibility,
        )

def rustleaks_integration_test(
        name,
        src,
        deps,
        edition = "2024",
        compile_data = [],
        data = [],
        env = {},
        crate_features = [],
        srcs = []):
    """Defines one Cargo integration-test binary as a Bazel test."""
    rust_test(
        name = name,
        aliases = aliases(normal = True, normal_dev = True),
        compile_data = compile_data,
        crate_features = crate_features,
        crate_name = name,
        crate_root = src,
        data = data,
        deps = all_crate_deps(normal = True, normal_dev = True) + deps,
        edition = edition,
        env = env,
        rustc_env = {
            "CARGO_MANIFEST_DIR": native.package_name(),
            "CARGO_PKG_VERSION": "0.1.0-alpha.4",
        },
        srcs = [src] + srcs,
        visibility = ["//visibility:public"],
    )
