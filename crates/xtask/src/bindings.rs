//! Release packaging for the Go and Python bindings.
//!
//! - `go-layout` writes the `rustleaks-go` repository: the main module from
//!   `bindings/go/`, one module per platform under `lib/` with the native
//!   library that the release built, and the main module's `go.sum`.
//! - `go-proxy` writes a file-based Go module proxy from that layout, so a
//!   dry run can build a program against the modules exactly as they would
//!   be published.
//! - `dry-run` builds and runs a Go program from the proxy, and installs the
//!   wheel into a new virtual environment without network access and runs a
//!   scan.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::tooling::{command_output, sha256_bytes};

/// Subcommands accepted after `bindings`.
pub(crate) const SUBCOMMANDS: &[&str] = &["go-layout", "go-proxy", "dry-run"];

/// The published Go module path.
const GO_MODULE: &str = "github.com/joshgarnett/rustleaks-go";

/// The time recorded in the proxy's `.info` files. Go only displays it.
const PROXY_TIME: &str = "2026-01-01T00:00:00Z";

/// One release platform of the Go module and the Python wheel.
struct Platform {
    /// The folder under `lib/`, also the last element of the module path.
    name: &'static str,
    /// The Bazel config of the native lane, without the `release-` prefix.
    config: &'static str,
    /// The Go build constraint for this platform.
    build: &'static str,
    description: &'static str,
    /// Linker flags after the static library, from rustc's
    /// `--print native-static-libs`. Empty on Windows.
    system_libraries: &'static str,
    /// The wheel platform tag that `//release/python:wheel` writes.
    wheel_tag: &'static str,
    windows: bool,
    musl: bool,
}

const PLATFORMS: &[Platform] = &[
    Platform {
        name: "darwin-amd64",
        config: "macos-x86_64",
        build: "darwin && amd64",
        description: "macOS on x86_64",
        system_libraries: "-lSystem -lc -lm",
        wheel_tag: "macosx_14_0_x86_64",
        windows: false,
        musl: false,
    },
    Platform {
        name: "darwin-arm64",
        config: "macos-aarch64",
        build: "darwin && arm64",
        description: "macOS on ARM64",
        system_libraries: "-lSystem -lc -lm",
        wheel_tag: "macosx_14_0_arm64",
        windows: false,
        musl: false,
    },
    Platform {
        name: "linux-amd64",
        config: "linux-x86_64-gnu",
        build: "linux && amd64 && !musl",
        description: "Linux on x86_64 with glibc",
        system_libraries: "-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc",
        wheel_tag: "manylinux_2_28_x86_64",
        windows: false,
        musl: false,
    },
    Platform {
        name: "linux-amd64-musl",
        config: "linux-x86_64-musl",
        build: "linux && amd64 && musl",
        description: "Linux on x86_64 with musl",
        system_libraries: "-lc",
        wheel_tag: "musllinux_1_2_x86_64",
        windows: false,
        musl: true,
    },
    Platform {
        name: "linux-arm64",
        config: "linux-aarch64-gnu",
        build: "linux && arm64 && !musl",
        description: "Linux on ARM64 with glibc",
        system_libraries: "-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc",
        wheel_tag: "manylinux_2_28_aarch64",
        windows: false,
        musl: false,
    },
    Platform {
        name: "linux-arm64-musl",
        config: "linux-aarch64-musl",
        build: "linux && arm64 && musl",
        description: "Linux on ARM64 with musl",
        system_libraries: "-lc",
        wheel_tag: "musllinux_1_2_aarch64",
        windows: false,
        musl: true,
    },
    Platform {
        name: "windows-amd64",
        config: "windows-x86_64-msvc",
        build: "windows && amd64",
        description: "Windows on x86_64",
        system_libraries: "",
        wheel_tag: "win_amd64",
        windows: true,
        musl: false,
    },
    Platform {
        name: "windows-arm64",
        config: "windows-aarch64-msvc",
        build: "windows && arm64",
        description: "Windows on ARM64",
        system_libraries: "",
        wheel_tag: "win_arm64",
        windows: true,
        musl: false,
    },
];

/// The file the Bazel static library target writes.
const STATIC_LIBRARY: &str = "librustleaks_ffi_static.a";
/// The static library's name in a platform module, for `-lrustleaks_ffi`.
const MODULE_STATIC_LIBRARY: &str = "librustleaks_ffi.a";
/// The DLL's name, which the Go package also uses for the extracted file.
const DLL: &str = "rustleaks_ffi.dll";

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    match args {
        [command, version, libraries, output] if command == "go-layout" => {
            go_layout(root, version, Path::new(libraries), Path::new(output)).map(|_| ())
        }
        [command, layout, proxy] if command == "go-proxy" => {
            go_proxy(Path::new(layout), Path::new(proxy)).map(|_| ())
        }
        [command, config, go_root, proxy, wheel, work, pythons @ ..]
            if command == "dry-run" && !pythons.is_empty() =>
        {
            dry_run(
                root,
                config,
                Path::new(go_root),
                Path::new(proxy),
                Path::new(wheel),
                Path::new(work),
                pythons,
            )
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    format!(
        "usage: cargo xtask bindings <{}> [ARGS]\n       {}",
        SUBCOMMANDS.join("|"),
        USAGE_LINES
    )
}

const USAGE_LINES: &str = "cargo xtask bindings go-layout <version> <libraries-dir> <output-dir>\n       \
     cargo xtask bindings go-proxy <layout-dir> <proxy-dir>\n       \
     cargo xtask bindings dry-run <config> <go-root> <proxy-dir> <wheel> <work-dir> <python>...";

fn platform_for_config(config: &str) -> Result<&'static Platform, String> {
    let config = config.strip_prefix("release-").unwrap_or(config);
    PLATFORMS
        .iter()
        .find(|platform| platform.config == config)
        .ok_or_else(|| format!("no binding platform for Bazel config {config}"))
}

fn check_version(version: &str) -> Result<(), String> {
    semver::Version::parse(version)
        .map(|_| ())
        .map_err(|error| format!("version {version:?} is not a semantic version: {error}"))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Replaces every `{{key}}` in a template and fails on unknown keys.
fn render(template: &str, values: &[(&str, &str)]) -> Result<String, String> {
    let mut text = template.to_owned();
    for (key, value) in values {
        text = text.replace(&format!("{{{{{key}}}}}"), value);
    }
    if let Some(start) = text.find("{{") {
        let end = text[start..]
            .find("}}")
            .map_or(text.len(), |end| start + end + 2);
        return Err(format!("template leaves {} unset", &text[start..end]));
    }
    Ok(text)
}

/// Returns the `go` directive of a go.mod file and rejects dependencies,
/// because the published main module requires only its own `lib` modules.
fn go_directive(go_mod: &str) -> Result<String, String> {
    let mut module = None;
    let mut go = None;
    for line in go_mod.lines().map(str::trim) {
        if let Some(path) = line.strip_prefix("module ") {
            module = Some(path.trim());
        } else if let Some(version) = line.strip_prefix("go ") {
            go = Some(version.trim().to_owned());
        } else if !line.is_empty() && !line.starts_with("//") {
            return Err(format!(
                "bindings/go/go.mod has an unexpected line {line:?}; the binding takes no Go dependencies"
            ));
        }
    }
    if module != Some(GO_MODULE) {
        return Err(format!(
            "bindings/go/go.mod must declare module {GO_MODULE}"
        ));
    }
    go.ok_or_else(|| "bindings/go/go.mod has no go directive".into())
}

/// Lists the files of the Go module rooted at `root` as module zip paths,
/// relative and with `/`. Folders that hold their own go.mod are other
/// modules and are left out, as `go mod` does.
fn module_files(root: &Path) -> Result<Vec<String>, String> {
    fn walk(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<(), String> {
        let mut entries = fs::read_dir(directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if kind.is_dir() {
                let name = entry.file_name();
                if name == ".git" || name == "vendor" || path.join("go.mod").exists() {
                    continue;
                }
                walk(root, &path, files)?;
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push(relative);
            } else {
                return Err(format!("{} is not a regular file", path.display()));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

/// Go's `h1:` hash (`golang.org/x/mod/sumdb/dirhash.Hash1`) over named
/// files: SHA-256 of the lines `<hex sha256 of file>  <name>\n`, sorted by
/// name, encoded in standard base64.
fn hash1<'a>(files: impl IntoIterator<Item = (String, &'a [u8])>) -> String {
    let mut files = files.into_iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut summary = Sha256::new();
    for (name, bytes) in files {
        summary.update(format!("{}  {name}\n", sha256_bytes(bytes)).as_bytes());
    }
    format!("h1:{}", STANDARD.encode(summary.finalize()))
}

/// The two go.sum lines of a module version: its zip and its go.mod.
fn go_sum_lines(module: &str, version: &str, root: &Path) -> Result<[String; 2], String> {
    let files = module_files(root)?;
    let contents = files
        .iter()
        .map(|file| read(&root.join(file)).map(|bytes| (file.clone(), bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    let zip = hash1(
        contents
            .iter()
            .map(|(file, bytes)| (format!("{module}@v{version}/{file}"), bytes.as_slice())),
    );
    let go_mod = read(&root.join("go.mod"))?;
    let go_mod = hash1([("go.mod".to_owned(), go_mod.as_slice())]);
    Ok([
        format!("{module} v{version} {zip}"),
        format!("{module} v{version}/go.mod {go_mod}"),
    ])
}

/// Copies `bindings/go/` without Bazel files and tests.
fn copy_go_sources(source: &Path, output: &Path) -> Result<(), String> {
    for file in module_files(source)? {
        let name = file.rsplit('/').next().unwrap_or(&file);
        let skipped = name == "BUILD.bazel"
            || name == "BUILD"
            || name == "go.mod"
            || name == "README.md"
            || name.ends_with("_test.go")
            || file.split('/').any(|part| part == "testdata");
        if !skipped {
            write(&output.join(&file), &read(&source.join(&file))?)?;
        }
    }
    Ok(())
}

/// Returns the version of the Go package from `bindings/go/library.go`.
fn go_package_version(library_go: &str) -> Result<&str, String> {
    library_go
        .lines()
        .find_map(|line| line.trim().strip_prefix("const packageVersion = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| "bindings/go/library.go has no packageVersion constant".into())
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    // A fixed header: no file name and modification time 0, so the output
    // depends only on the input.
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(bytes)
        .and_then(|()| encoder.finish())
        .map_err(|error| format!("cannot compress the DLL: {error}"))
}

/// Writes the `rustleaks-go` repository for `version` into `output`.
///
/// `libraries` holds one folder per platform, named as under `lib/`, with
/// the release build's `librustleaks_ffi_static.a` or `rustleaks_ffi.dll`.
/// Returns the go.sum lines of the `lib` modules.
fn go_layout(
    root: &Path,
    version: &str,
    libraries: &Path,
    output: &Path,
) -> Result<Vec<String>, String> {
    go_layout_from(root, &root.join("bindings/go"), version, libraries, output)
}

/// [`go_layout`] with the Go package read from `source`.
fn go_layout_from(
    root: &Path,
    source: &Path,
    version: &str,
    libraries: &Path,
    output: &Path,
) -> Result<Vec<String>, String> {
    check_version(version)?;
    if output.exists() {
        return Err(format!("{} already exists", output.display()));
    }
    let templates = root.join("release/go/templates");
    let package_version = read_text(&source.join("library.go"))?;
    let package_version = go_package_version(&package_version)?;
    if package_version != version {
        return Err(format!(
            "bindings/go/library.go is version {package_version}, not {version}"
        ));
    }
    let go_version = go_directive(&read_text(&source.join("go.mod"))?)?;
    let license = read(&root.join("LICENSE"))?;
    let notice = read(&root.join("NOTICE"))?;

    copy_go_sources(source, output)?;
    for (file, bytes) in [("LICENSE", &license), ("NOTICE", &notice)] {
        write(&output.join(file), bytes)?;
    }
    for file in ["README.md", "CONTRIBUTING.md"] {
        let text = render(
            &read_text(&root.join("release/go").join(file))?,
            &[("version", version)],
        )?;
        write(&output.join(file), text.as_bytes())?;
    }

    let mut sums = Vec::new();
    let mut requires = String::new();
    for platform in PLATFORMS {
        let module = format!("{GO_MODULE}/lib/{}", platform.name);
        let directory = output.join("lib").join(platform.name);
        let input = libraries.join(platform.name);
        let values_build = [
            ("build", platform.build),
            ("description", platform.description),
            ("platform", platform.name),
            ("version", version),
            ("go_version", go_version.as_str()),
        ];
        let lib_go = if platform.windows {
            let dll = read(&input.join(DLL))?;
            let compressed = gzip(&dll)?;
            let dll_sha256 = sha256_bytes(&dll);
            let gzip_sha256 = sha256_bytes(&compressed);
            write(&directory.join(format!("{DLL}.gz")), &compressed)?;
            let mut values = values_build.to_vec();
            values.push(("dll_sha256", &dll_sha256));
            values.push(("gzip_sha256", &gzip_sha256));
            render(&read_text(&templates.join("lib_windows.go.tmpl"))?, &values)?
        } else {
            write(
                &directory.join(MODULE_STATIC_LIBRARY),
                &read(&input.join(STATIC_LIBRARY))?,
            )?;
            let mut values = values_build.to_vec();
            values.push(("system_libraries", platform.system_libraries));
            render(&read_text(&templates.join("lib_unix.go.tmpl"))?, &values)?
        };
        write(&directory.join("lib.go"), lib_go.as_bytes())?;
        let go_mod = render(
            &read_text(&templates.join("lib.go.mod.tmpl"))?,
            &values_build,
        )?;
        write(&directory.join("go.mod"), go_mod.as_bytes())?;
        write(&directory.join("LICENSE"), &license)?;
        write(&directory.join("NOTICE"), &notice)?;

        let import = if platform.windows {
            "import_windows.go.tmpl"
        } else {
            "import_unix.go.tmpl"
        };
        let import = render(&read_text(&templates.join(import))?, &values_build)?;
        write(
            &output.join(format!("library_{}.go", platform.name)),
            import.as_bytes(),
        )?;

        sums.extend(go_sum_lines(&module, version, &directory)?);
        requires.push_str(&format!("\t{module} v{version}\n"));
    }

    let go_mod = format!("module {GO_MODULE}\n\ngo {go_version}\n\nrequire (\n{requires})\n");
    write(&output.join("go.mod"), go_mod.as_bytes())?;
    sums.sort();
    let go_sum = sums
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    write(&output.join("go.sum"), go_sum.as_bytes())?;
    println!(
        "wrote the {GO_MODULE} v{version} layout with {} platform modules to {}",
        PLATFORMS.len(),
        output.display()
    );
    Ok(sums)
}

/// The modules of a layout: the main module and each `lib` module, as
/// (module path, folder).
fn layout_modules(layout: &Path) -> Vec<(String, PathBuf)> {
    std::iter::once((GO_MODULE.to_owned(), layout.to_path_buf()))
        .chain(PLATFORMS.iter().map(|platform| {
            (
                format!("{GO_MODULE}/lib/{}", platform.name),
                layout.join("lib").join(platform.name),
            )
        }))
        .collect()
}

/// Reads the version from the `require` lines of the layout's go.mod.
fn layout_version(layout: &Path) -> Result<String, String> {
    let go_mod = read_text(&layout.join("go.mod"))?;
    let mut versions = go_mod
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&format!("{GO_MODULE}/lib/")))
        .filter_map(|rest| rest.split_whitespace().nth(1))
        .filter_map(|version| version.strip_prefix('v'))
        .collect::<BTreeSet<_>>();
    match (versions.pop_first(), versions.is_empty()) {
        (Some(version), true) => Ok(version.to_owned()),
        _ => Err(format!(
            "{} must require every lib module at one version",
            layout.display()
        )),
    }
}

/// Writes a file-based module proxy (`GOPROXY=file://...`) for every module
/// of a layout, and `go.sum` lines for all of them in `hashes.txt`.
fn go_proxy(layout: &Path, proxy: &Path) -> Result<Vec<String>, String> {
    let version = layout_version(layout)?;
    check_version(&version)?;
    if proxy.exists() {
        return Err(format!("{} already exists", proxy.display()));
    }
    let mut hashes = Vec::new();
    for (module, directory) in layout_modules(layout) {
        let files = module_files(&directory)?;
        let mut entries = Vec::new();
        for file in &files {
            entries.push((
                format!("{module}@v{version}/{file}"),
                read(&directory.join(file))?,
            ));
        }
        let versions = proxy.join(escape_module_path(&module)).join("@v");
        write(&versions.join("list"), format!("v{version}\n").as_bytes())?;
        write(
            &versions.join(format!("v{version}.info")),
            format!("{{\"Version\":\"v{version}\",\"Time\":\"{PROXY_TIME}\"}}\n").as_bytes(),
        )?;
        write(
            &versions.join(format!("v{version}.mod")),
            &read(&directory.join("go.mod"))?,
        )?;
        write(
            &versions.join(format!("v{version}.zip")),
            &stored_zip(&entries)?,
        )?;
        hashes.extend(go_sum_lines(&module, &version, &directory)?);
    }
    hashes.sort();
    let text = hashes
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    write(&proxy.join("hashes.txt"), text.as_bytes())?;
    println!(
        "wrote a module proxy for {} modules at v{version} to {}",
        hashes.len() / 2,
        proxy.display()
    );
    Ok(hashes)
}

/// Escapes a module path for a proxy URL: each capital letter becomes `!`
/// and the lowercase letter.
fn escape_module_path(module: &str) -> String {
    let mut escaped = String::new();
    for character in module.chars() {
        if character.is_ascii_uppercase() {
            escaped.push('!');
            escaped.push(character.to_ascii_lowercase());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Writes a zip archive whose entries are stored without compression. Go
/// reads stored entries, and the module hash depends only on the names and
/// contents, not on the compression.
fn stored_zip(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut archive = Vec::new();
    let mut directory = Vec::new();
    for (name, bytes) in entries {
        let offset = u32::try_from(archive.len()).map_err(|_| "zip archive over 4 GiB")?;
        let size = u32::try_from(bytes.len()).map_err(|_| format!("{name} is over 4 GiB"))?;
        let name_length = u16::try_from(name.len()).map_err(|_| format!("{name} is too long"))?;
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        let crc = crc.sum();
        // Local file header: version 2.0, UTF-8 names, stored, DOS date
        // 1980-01-01.
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
        local.extend_from_slice(&20_u16.to_le_bytes());
        local.extend_from_slice(&0x0800_u16.to_le_bytes());
        local.extend_from_slice(&0_u16.to_le_bytes());
        local.extend_from_slice(&0_u16.to_le_bytes());
        local.extend_from_slice(&0x0021_u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&name_length.to_le_bytes());
        local.extend_from_slice(&0_u16.to_le_bytes());
        archive.extend_from_slice(&local);
        archive.extend_from_slice(name.as_bytes());
        archive.extend_from_slice(bytes);

        directory.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        directory.extend_from_slice(&20_u16.to_le_bytes());
        directory.extend_from_slice(&local[4..30]);
        directory.extend_from_slice(&0_u16.to_le_bytes());
        directory.extend_from_slice(&0_u16.to_le_bytes());
        directory.extend_from_slice(&0_u16.to_le_bytes());
        directory.extend_from_slice(&0_u32.to_le_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let count = u16::try_from(entries.len()).map_err(|_| "too many zip entries")?;
    let directory_offset = u32::try_from(archive.len()).map_err(|_| "zip archive over 4 GiB")?;
    let directory_size = u32::try_from(directory.len()).map_err(|_| "zip directory over 4 GiB")?;
    archive.extend_from_slice(&directory);
    archive.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&directory_size.to_le_bytes());
    archive.extend_from_slice(&directory_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    Ok(archive)
}

/// Resolves a path to an absolute one. On Windows it drops the `\\?\`
/// prefix that `canonicalize` adds, because Go does not match `go:embed`
/// patterns under such a path.
fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    let absolute = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    let text = absolute.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => Ok(PathBuf::from(rest)),
        _ => Ok(absolute),
    }
}

/// Turns a local folder into a `file://` URL that Go accepts on every
/// system.
fn file_url(path: &Path) -> Result<String, String> {
    let absolute = absolute_path(path)?;
    let text = absolute.to_string_lossy().replace('\\', "/");
    let text = text.strip_prefix("//?/").unwrap_or(&text);
    if text.starts_with('/') {
        Ok(format!("file://{text}"))
    } else {
        Ok(format!("file:///{text}"))
    }
}

/// Builds and runs a Go program and installs and runs the wheel, as a user
/// on this lane would.
fn dry_run(
    root: &Path,
    config: &str,
    go_root: &Path,
    proxy: &Path,
    wheel: &Path,
    work: &Path,
    pythons: &[String],
) -> Result<(), String> {
    let platform = platform_for_config(config)?;
    if work.exists() {
        return Err(format!("{} already exists", work.display()));
    }
    fs::create_dir_all(work)
        .map_err(|error| format!("cannot create {}: {error}", work.display()))?;
    let work = absolute_path(work)?;
    go_dry_run(root, platform, go_root, proxy, &work)?;
    for (index, python) in pythons.iter().enumerate() {
        let venv = work.join(format!("venv-{index}"));
        python_dry_run(root, platform, Path::new(python), wheel, &venv)?;
    }
    println!("binding dry run passed for {}", platform.name);
    Ok(())
}

fn go_dry_run(
    root: &Path,
    platform: &Platform,
    go_root: &Path,
    proxy: &Path,
    work: &Path,
) -> Result<(), String> {
    let hashes = read_text(&proxy.join("hashes.txt"))?;
    let version = hashes
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{GO_MODULE} v")))
        .and_then(|rest| rest.split_whitespace().next())
        .filter(|version| !version.ends_with("/go.mod"))
        .ok_or("hashes.txt has no main module line")?
        .to_owned();
    let consumer = work.join("go-program");
    let go_mod = format!(
        "module example.com/rustleaksdryrun\n\ngo 1.27\n\nrequire {GO_MODULE} v{version}\n"
    );
    write(&consumer.join("go.mod"), go_mod.as_bytes())?;
    write(
        &consumer.join("main.go"),
        &read(&root.join("release/go/dryrun/main.go"))?,
    )?;

    let go = go_root
        .join("bin")
        .join(if platform.windows { "go.exe" } else { "go" });
    let proxy_url = file_url(proxy)?;
    let configure = |command: &mut Command| {
        command
            .current_dir(&consumer)
            .env("GOROOT", go_root)
            .env("GOPROXY", &proxy_url)
            .env("GOSUMDB", "off")
            .env("GOFLAGS", "-mod=mod")
            .env("GOTOOLCHAIN", "local")
            .env("GOWORK", "off")
            .env("GOENV", "off")
            .env("GOMODCACHE", work.join("go-modules"))
            .env("GOCACHE", work.join("go-cache"))
            .env("GOPATH", work.join("go-path"))
            .env("CGO_ENABLED", if platform.windows { "0" } else { "1" });
        if platform.musl {
            command.env("CC", "musl-gcc");
        }
        if platform.windows {
            // The package writes the embedded DLL under the user cache
            // folder; keep it inside the dry run folder.
            command.env("LOCALAPPDATA", work.join("cache"));
        }
    };
    let go_command = |args: &[&str]| {
        let mut command = Command::new(&go);
        configure(&mut command);
        command.args(args);
        command
    };
    command_output(&mut go_command(&["mod", "tidy"]))?;
    let output = if platform.windows {
        "dryrun.exe"
    } else {
        "dryrun"
    };
    let mut build = vec!["build", "-trimpath", "-o", output];
    if platform.musl {
        build.extend([
            "-tags",
            "musl",
            "-ldflags=-linkmode=external -extldflags=-static",
        ]);
    }
    build.push(".");
    command_output(&mut go_command(&build))?;
    let program = consumer.join(output);
    let mut run = Command::new(&program);
    configure(&mut run);
    let result = command_output(&mut run)?;
    if !result.contains("found aws-access-token") {
        return Err(format!("the Go program printed {result:?}"));
    }
    println!("Go program: {result}");

    // Every go.sum line the program recorded must match the hashes that
    // xtask computed for the layout, and the main module's own go.sum.
    let recorded = read_text(&consumer.join("go.sum"))?;
    let expected = hashes.lines().collect::<BTreeSet<_>>();
    let recorded = recorded.lines().collect::<BTreeSet<_>>();
    if let Some(line) = recorded.difference(&expected).next() {
        return Err(format!(
            "go recorded a hash that xtask did not compute: {line}"
        ));
    }
    for module in [
        GO_MODULE.to_owned(),
        format!("{GO_MODULE}/lib/{}", platform.name),
    ] {
        let prefix = format!("{module} v{version} ");
        if !recorded.iter().any(|line| line.starts_with(&prefix)) {
            return Err(format!("go.sum of the Go program has no line for {module}"));
        }
    }
    if platform.musl {
        check_static(&program)?;
    }
    Ok(())
}

fn check_static(program: &Path) -> Result<(), String> {
    let headers = command_output(
        Command::new("readelf")
            .arg("--program-headers")
            .arg(program),
    )?;
    if headers.contains(" INTERP ") {
        return Err(format!("{} has a dynamic interpreter", program.display()));
    }
    Ok(())
}

/// Installs the wheel into a new virtual environment at `venv` made by
/// `python`, without network access, and runs `release/python/dryrun.py`.
fn python_dry_run(
    root: &Path,
    platform: &Platform,
    python: &Path,
    wheel: &Path,
    venv: &Path,
) -> Result<(), String> {
    let work = venv
        .parent()
        .ok_or("the virtual environment has no parent folder")?;
    let name = wheel
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("the wheel path has no file name")?;
    let version = read_text(&root.join("bindings/python/src/rustleaks/_version.py"))?;
    let version = version
        .lines()
        .find_map(|line| line.strip_prefix("__version__ = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or("_version.py has no __version__")?;
    let expected = format!("rustleaks-{version}-py3-none-{}.whl", platform.wheel_tag);
    if name != expected {
        return Err(format!("wheel is named {name}, expected {expected}"));
    }

    command_output(
        Command::new(python)
            .args(["-I", "-m", "venv"])
            .arg(venv)
            .current_dir(work),
    )?;
    let venv_python = if platform.windows {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    };
    command_output(
        Command::new(&venv_python)
            .args([
                "-I",
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--disable-pip-version-check",
            ])
            .arg(wheel)
            .env(
                "PIP_CONFIG_FILE",
                if platform.windows { "NUL" } else { "/dev/null" },
            )
            .current_dir(work),
    )?;
    let result = command_output(
        Command::new(&venv_python)
            .arg("-I")
            .arg(root.join("release/python/dryrun.py"))
            .arg(root.join("bindings/python/pyproject.toml"))
            .current_dir(work),
    )?;
    println!("Python program: {result}");
    if !platform.windows {
        let library = command_output(
            Command::new(&venv_python)
                .args([
                    "-I",
                    "-c",
                    "import rustleaks._native as n; print(n.default_library_path())",
                ])
                .current_dir(work),
        )?;
        check_library_dependencies(platform, Path::new(library.trim()))?;
    }
    Ok(())
}

/// Checks that the installed shared library needs only system libraries:
/// glibc 2.28 or older symbols on GNU Linux, only `libc.so` on musl, and
/// only system libraries on macOS.
fn check_library_dependencies(platform: &Platform, library: &Path) -> Result<(), String> {
    if platform.config.starts_with("macos") {
        let output = command_output(Command::new("otool").arg("-L").arg(library))?;
        for line in output.lines().skip(1) {
            let dependency = line.trim().split(' ').next().unwrap_or_default();
            let allowed = dependency.starts_with("/usr/lib/")
                || dependency.starts_with("/System/Library/")
                || dependency.ends_with("librustleaks_ffi.dylib");
            if !allowed {
                return Err(format!("{} needs {dependency}", library.display()));
            }
        }
        return Ok(());
    }
    let dynamic = command_output(Command::new("readelf").arg("--dynamic").arg(library))?;
    let needed = dynamic
        .lines()
        .filter(|line| line.contains("(NEEDED)"))
        .filter_map(|line| line.split('[').nth(1)?.split(']').next())
        .collect::<Vec<_>>();
    let allowed: &[&str] = if platform.musl {
        &["libc.so"]
    } else {
        &[
            "libc.so.6",
            "libm.so.6",
            "libdl.so.2",
            "libpthread.so.0",
            "librt.so.1",
            "ld-linux-x86-64.so.2",
            "ld-linux-aarch64.so.1",
        ]
    };
    if let Some(extra) = needed.iter().find(|name| !allowed.contains(name)) {
        return Err(format!("{} needs {extra}", library.display()));
    }
    if !platform.musl {
        let versions = command_output(Command::new("readelf").arg("--version-info").arg(library))?;
        let newest = versions
            .split_whitespace()
            .filter_map(|word| word.strip_prefix("GLIBC_"))
            .filter_map(|version| {
                let mut parts = version.split('.').map(str::parse::<u32>);
                Some((
                    parts.next()?.ok()?,
                    parts.next().and_then(Result::ok).unwrap_or(0),
                ))
            })
            .max()
            .ok_or("the library names no glibc symbol version")?;
        if newest > (2, 28) {
            return Err(format!(
                "{} needs GLIBC_{}.{}, newer than its manylinux_2_28 tag allows",
                library.display(),
                newest.0,
                newest.1
            ));
        }
    }
    Ok(())
}

/// The release versions that the binding files name, for the version check.
pub(crate) fn binding_versions(root: &Path) -> Result<BTreeMap<&'static str, String>, String> {
    let mut versions = BTreeMap::new();
    let library = read_text(&root.join("bindings/go/library.go"))?;
    versions.insert(
        "bindings/go/library.go",
        go_package_version(&library)?.to_owned(),
    );
    let pyproject = read_text(&root.join("bindings/python/pyproject.toml"))?;
    let pyproject = pyproject
        .parse::<toml::Table>()
        .map_err(|error| format!("cannot parse bindings/python/pyproject.toml: {error}"))?;
    let version = pyproject
        .get("project")
        .and_then(|project| project.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or("bindings/python/pyproject.toml has no project.version")?;
    versions.insert("bindings/python/pyproject.toml", version.to_owned());
    let version_py = read_text(&root.join("bindings/python/src/rustleaks/_version.py"))?;
    let version = version_py
        .lines()
        .find_map(|line| line.strip_prefix("__version__ = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or("bindings/python/src/rustleaks/_version.py has no __version__")?;
    versions.insert(
        "bindings/python/src/rustleaks/_version.py",
        version.to_owned(),
    );
    Ok(versions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tooling::ScopedTempDir;

    #[test]
    fn hash1_matches_the_dirhash_definition() {
        // dirhash.Hash1 hashes "<sha256 hex>  <name>\n" lines in name order.
        let a = sha256_bytes(b"alpha");
        let b = sha256_bytes(b"beta");
        let summary = format!("{a}  a.txt\n{b}  b/c.txt\n");
        let expected = format!("h1:{}", STANDARD.encode(Sha256::digest(summary.as_bytes())));
        let actual = hash1([
            ("b/c.txt".to_owned(), b"beta".as_slice()),
            ("a.txt".to_owned(), b"alpha".as_slice()),
        ]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn module_files_leave_out_nested_modules() {
        let temp = ScopedTempDir::new("bindings-module-files").unwrap();
        let root = &temp.path;
        write(&root.join("go.mod"), b"module example.com/a\n").unwrap();
        write(&root.join("a.go"), b"package a\n").unwrap();
        write(&root.join("internal/b.go"), b"package b\n").unwrap();
        write(&root.join("lib/x/go.mod"), b"module example.com/a/lib/x\n").unwrap();
        write(&root.join("lib/x/x.go"), b"package x\n").unwrap();
        assert_eq!(
            module_files(root).unwrap(),
            ["a.go", "go.mod", "internal/b.go"]
        );
    }

    #[test]
    fn go_directive_rejects_dependencies() {
        assert_eq!(
            go_directive("module github.com/joshgarnett/rustleaks-go\n\ngo 1.27\n").unwrap(),
            "1.27"
        );
        assert!(
            go_directive("module github.com/joshgarnett/rustleaks-go\ngo 1.27\nrequire x v1\n")
                .is_err()
        );
        assert!(go_directive("module example.com/other\ngo 1.27\n").is_err());
    }

    #[test]
    fn render_fails_on_unset_keys() {
        assert_eq!(render("a {{x}} b", &[("x", "1")]).unwrap(), "a 1 b");
        assert!(render("a {{y}}", &[("x", "1")]).is_err());
    }

    #[test]
    fn stored_zip_has_one_record_per_entry() {
        let zip = stored_zip(&[
            ("m@v1.0.0/go.mod".to_owned(), b"module m\n".to_vec()),
            ("m@v1.0.0/a.go".to_owned(), b"package m\n".to_vec()),
        ])
        .unwrap();
        assert_eq!(&zip[..4], &0x0403_4b50_u32.to_le_bytes());
        let end = zip.len() - 22;
        assert_eq!(&zip[end..end + 4], &0x0605_4b50_u32.to_le_bytes());
        assert_eq!(u16::from_le_bytes([zip[end + 10], zip[end + 11]]), 2);
    }

    #[test]
    fn every_platform_has_a_distinct_folder_config_and_wheel_tag() {
        let names = PLATFORMS.iter().map(|p| p.name).collect::<BTreeSet<_>>();
        let configs = PLATFORMS.iter().map(|p| p.config).collect::<BTreeSet<_>>();
        let tags = PLATFORMS
            .iter()
            .map(|p| p.wheel_tag)
            .collect::<BTreeSet<_>>();
        assert_eq!((names.len(), configs.len(), tags.len()), (8, 8, 8));
        for target in crate::REQUIRED_TARGETS {
            let config = match *target {
                "x86_64-unknown-linux-gnu" => "linux-x86_64-gnu",
                "aarch64-unknown-linux-gnu" => "linux-aarch64-gnu",
                "x86_64-unknown-linux-musl" => "linux-x86_64-musl",
                "aarch64-unknown-linux-musl" => "linux-aarch64-musl",
                "x86_64-apple-darwin" => "macos-x86_64",
                "aarch64-apple-darwin" => "macos-aarch64",
                "x86_64-pc-windows-msvc" => "windows-x86_64-msvc",
                "aarch64-pc-windows-msvc" => "windows-aarch64-msvc",
                other => panic!("unexpected target {other}"),
            };
            assert!(configs.contains(config), "{config}");
            assert!(platform_for_config(&format!("release-{config}")).is_ok());
        }
    }

    #[test]
    fn layout_and_proxy_agree_on_hashes() {
        let root = crate::workspace_root().unwrap();
        let temp = ScopedTempDir::new("bindings-layout").unwrap();
        let libraries = temp.path.join("libraries");
        for platform in PLATFORMS {
            let file = if platform.windows {
                DLL
            } else {
                STATIC_LIBRARY
            };
            write(
                &libraries.join(platform.name).join(file),
                format!("synthetic {}", platform.name).as_bytes(),
            )
            .unwrap();
        }
        let version = "1.2.3";
        let source = temp.path.join("source");
        write(
            &source.join("go.mod"),
            format!("module {GO_MODULE}\n\ngo 1.27\n").as_bytes(),
        )
        .unwrap();
        write(
            &source.join("library.go"),
            b"package rustleaks\n\nconst packageVersion = \"1.2.3\"\n",
        )
        .unwrap();
        write(&source.join("library_test.go"), b"package rustleaks\n").unwrap();
        write(&source.join("BUILD.bazel"), b"# Bazel\n").unwrap();
        let layout = temp.path.join("layout");
        let sums = go_layout_from(&root, &source, version, &libraries, &layout).unwrap();
        assert_eq!(sums.len(), 2 * PLATFORMS.len());
        let go_mod = read_text(&layout.join("go.mod")).unwrap();
        assert!(go_mod.contains(&format!("{GO_MODULE}/lib/windows-arm64 v{version}")));
        assert!(layout.join("library.go").is_file());
        assert!(!layout.join("library_test.go").exists());
        let windows = read_text(&layout.join("lib/windows-amd64/lib.go")).unwrap();
        assert!(windows.contains(&format!(
            "DLLSHA256 = \"{}\"",
            sha256_bytes(b"synthetic windows-amd64")
        )));
        let linux = read_text(&layout.join("lib/linux-amd64/lib.go")).unwrap();
        assert!(linux.starts_with("//go:build linux && amd64 && !musl\n"));
        assert!(
            layout
                .join("lib/linux-amd64-musl/librustleaks_ffi.a")
                .is_file()
        );
        assert!(
            layout
                .join("lib/windows-amd64/rustleaks_ffi.dll.gz")
                .is_file()
        );
        assert!(!layout.join("BUILD.bazel").exists());
        assert!(
            module_files(&layout)
                .unwrap()
                .iter()
                .all(|file| !file.ends_with("_test.go"))
        );
        let proxy = temp.path.join("proxy");
        let hashes = go_proxy(&layout, &proxy).unwrap();
        for line in sums {
            assert!(hashes.contains(&line), "{line}");
        }
        assert!(
            proxy
                .join(format!("{GO_MODULE}/lib/darwin-arm64/@v/v{version}.zip"))
                .is_file()
        );
    }
}
