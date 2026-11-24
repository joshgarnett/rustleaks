//! Debian and RPM packages built from the verified GNU release archive.
//!
//! `//release/linux-packages` builds the packages with `rules_pkg` from the
//! input that [`write_input`] extracts. The checks here read the finished
//! packages and require that they install exactly the archive's binary and
//! documents, owned by root, with no maintainer scripts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::Path;

use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};

use super::notices;
use crate::tooling::{hex_lower, sha256_bytes};

const BINARY_PATH: &str = "usr/bin/rustleaks";
const DOC_ROOT: &str = "usr/share/doc/rustleaks";
const PACKAGE_NAME: &str = "rustleaks";
const RPM_RELEASE: &str = "1";
const MAX_PACKAGE_BYTES: u64 = super::MAX_NATIVE_ARCHIVE_BYTES + 4 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: u64 = super::MAX_NATIVE_ARCHIVE_BYTES;
const MAX_CONTROL_BYTES: u64 = 64 * 1024;
const MAX_ENTRIES: usize = 8192;

/// RPM header tags that run code at install, erase, verify or transaction
/// time, from `rpmtag.h`: scripts, their interpreters (`*PROG`), triggers
/// and file triggers.
const RPM_SCRIPT_TAGS: &[u32] = &[
    1023, 1024, 1025, 1026, // PREIN, POSTIN, PREUN, POSTUN
    1065, 1066, 1079, // TRIGGERSCRIPTS, TRIGGERNAME, VERIFYSCRIPT
    1085, 1086, 1087, 1088, // PREINPROG, POSTINPROG, PREUNPROG, POSTUNPROG
    1091, 1092, // VERIFYSCRIPTPROG, TRIGGERSCRIPTPROG
    1151, 1152, 1153, 1154, // PRETRANS, POSTTRANS and their PROG tags
    5066, 5067, 5069, // FILETRIGGERSCRIPTS, FILETRIGGERSCRIPTPROG, FILETRIGGERNAME
    5076, 5077, 5079, // the same for transaction file triggers
    5104, 5105, 5106, 5107, // PREUNTRANS, POSTUNTRANS and their PROG tags
];

/// RPM relationship tags the package must not carry: CONFLICTNAME,
/// OBSOLETENAME, RECOMMENDNAME, SUGGESTNAME, SUPPLEMENTNAME, ENHANCENAME.
const RPM_RELATION_TAGS: &[(u32, &str)] = &[
    (1054, "Conflicts"),
    (1090, "Obsoletes"),
    (5046, "Recommends"),
    (5049, "Suggests"),
    (5052, "Supplements"),
    (5055, "Enhances"),
];

/// RPM file flags that only mark documentation and license files.
const RPMFILE_DOC: u32 = 1 << 1;
const RPMFILE_LICENSE: u32 = 1 << 7;

/// Package metadata that each package must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) version: String,
    pub(super) deb_architecture: &'static str,
    pub(super) rpm_architecture: &'static str,
    pub(super) depends: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    size: u64,
    sha256: String,
    mode: u32,
}

/// The files and directories that a package must install.
#[derive(Debug)]
pub(super) struct Contents {
    files: BTreeMap<String, Member>,
    required_directories: BTreeSet<String>,
    allowed_directories: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct Observed {
    files: BTreeMap<String, Member>,
    directories: BTreeMap<String, u32>,
}

/// Returns the package version for a release version. Debian and RPM sort
/// `~` before the empty string, so `0.2.0-alpha.1` becomes `0.2.0~alpha.1`
/// and sorts before `0.2.0`. `release/linux-packages/BUILD.bazel` applies
/// the same rule.
pub(super) fn package_version(release_version: &str) -> String {
    release_version.replace('-', "~")
}

pub(super) fn identity(
    target: &str,
    release_version: &str,
    glibc: &str,
) -> Result<Identity, String> {
    let (deb_architecture, rpm_architecture) = match target {
        "x86_64-unknown-linux-gnu" => ("amd64", "x86_64"),
        "aarch64-unknown-linux-gnu" => ("arm64", "aarch64"),
        _ => return Err(format!("{target} has no Linux packages")),
    };
    let minimum = glibc
        .strip_prefix("GLIBC_")
        .filter(|version| {
            !version.is_empty()
                && version
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .ok_or_else(|| format!("glibc baseline {glibc:?} is not of the form GLIBC_X.Y"))?;
    Ok(Identity {
        version: package_version(release_version),
        deb_architecture,
        rpm_architecture,
        depends: format!("libc6 (>= {minimum})"),
    })
}

/// Maps the archive documents and binary to the paths the packages install.
pub(super) fn contents(
    documents: &BTreeMap<String, (Vec<u8>, u32)>,
    binary_sha256: &str,
    binary_size: u64,
) -> Result<Contents, String> {
    let mut files = BTreeMap::new();
    files.insert(
        BINARY_PATH.to_owned(),
        Member {
            size: binary_size,
            sha256: binary_sha256.to_owned(),
            mode: 0o755,
        },
    );
    let mut required_directories = BTreeSet::from([DOC_ROOT.to_owned()]);
    for (name, (bytes, _)) in documents {
        notices::portable_path(name)?;
        let path = format!("{DOC_ROOT}/{name}");
        let mut parent = path.as_str();
        while let Some((directory, _)) = parent.rsplit_once('/') {
            if directory.len() <= DOC_ROOT.len() {
                break;
            }
            required_directories.insert(directory.to_owned());
            parent = directory;
        }
        files.insert(
            path,
            Member {
                size: bytes.len() as u64,
                sha256: sha256_bytes(bytes),
                mode: 0o644,
            },
        );
    }
    let mut allowed_directories = required_directories.clone();
    for ancestor in ["usr", "usr/bin", "usr/share", "usr/share/doc"] {
        allowed_directories.insert(ancestor.to_owned());
    }
    Ok(Contents {
        files,
        required_directories,
        allowed_directories,
    })
}

/// Writes the `rules_pkg` input: `rustleaks`, `doc/` and `depends.txt`.
pub(super) fn write_input(
    output: &Path,
    documents: &BTreeMap<String, (Vec<u8>, u32)>,
    binary: &[u8],
    identity: &Identity,
) -> Result<(), String> {
    super::prepare_output_directory(output)?;
    let binary_path = output.join("rustleaks");
    fs::write(&binary_path, binary)
        .map_err(|error| format!("cannot write package input binary: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot mark package input binary executable: {error}"))?;
    }
    for (name, (bytes, _)) in documents {
        notices::portable_path(name)?;
        let path = output.join("doc").join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create package input folder: {error}"))?;
        }
        fs::write(&path, bytes)
            .map_err(|error| format!("cannot write package input document {name}: {error}"))?;
    }
    fs::write(
        output.join("depends.txt"),
        format!("{}\n", identity.depends),
    )
    .map_err(|error| format!("cannot write package dependencies: {error}"))
}

pub(super) fn verify_deb(
    path: &Path,
    contents: &Contents,
    identity: &Identity,
) -> Result<(), String> {
    let bytes = read_package(path)?;
    let members = ar_members(&bytes)?;
    let names = members.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    if names != ["debian-binary", "control.tar.gz", "data.tar.gz"] {
        return Err(format!("Debian package has members {names:?}"));
    }
    if members[0].1 != b"2.0\n" {
        return Err("Debian package is not format 2.0".into());
    }
    let control = gunzip(members[1].1, MAX_CONTROL_BYTES)?;
    let mut control_files = Observed::default();
    read_tar(&control, &mut control_files)?;
    if control_files.files.len() != 1
        || control_files
            .directories
            .keys()
            .any(|directory| !directory.is_empty())
    {
        return Err("Debian control archive holds files other than control".into());
    }
    let control_text = read_tar_file(&control, "control")?;
    let fields = control_fields(&control_text)?;
    for (field, expected) in [
        ("Package", PACKAGE_NAME),
        ("Version", identity.version.as_str()),
        ("Architecture", identity.deb_architecture),
        ("Depends", identity.depends.as_str()),
    ] {
        if fields.get(field).map(String::as_str) != Some(expected) {
            return Err(format!(
                "Debian control field {field} is {:?}, expected {expected:?}",
                fields.get(field)
            ));
        }
    }
    for field in ["Pre-Depends", "Conflicts", "Breaks", "Replaces", "Provides"] {
        if fields.contains_key(field) {
            return Err(format!("Debian control has unexpected field {field}"));
        }
    }
    let data = gunzip(members[2].1, MAX_PAYLOAD_BYTES)?;
    let mut observed = Observed::default();
    read_tar(&data, &mut observed)?;
    observed.directories.remove("");
    contents.check(&observed, "Debian package")
}

pub(super) fn verify_rpm(
    path: &Path,
    contents: &Contents,
    identity: &Identity,
) -> Result<(), String> {
    let bytes = read_package(path)?;
    if bytes.len() < 96 || bytes[..4] != [0xed, 0xab, 0xee, 0xdb] || bytes[4] != 3 {
        return Err("RPM package has no version 3 lead".into());
    }
    if bytes[6..8] != [0, 0] {
        return Err("RPM package is not a binary package".into());
    }
    let (_, signature_end) = rpm_header(&bytes, 96)?;
    let header_start = signature_end
        .checked_next_multiple_of(8)
        .ok_or("RPM signature header size overflow")?;
    let (header, payload_start) = rpm_header(&bytes, header_start)?;
    for (tag, name, expected) in [
        (1000, "name", PACKAGE_NAME),
        (1001, "version", identity.version.as_str()),
        (1002, "release", RPM_RELEASE),
        (1022, "architecture", identity.rpm_architecture),
        (1124, "payload format", "cpio"),
        (1125, "payload compressor", "gzip"),
    ] {
        let actual = header.string(tag)?;
        if actual != expected {
            return Err(format!("RPM {name} is {actual:?}, expected {expected:?}"));
        }
    }
    if let Some(tag) = RPM_SCRIPT_TAGS
        .iter()
        .find(|tag| header.entries.contains_key(tag))
    {
        return Err(format!("RPM package has script or trigger tag {tag}"));
    }
    if let Some((_, name)) = RPM_RELATION_TAGS
        .iter()
        .find(|(tag, _)| header.entries.contains_key(tag))
    {
        return Err(format!("RPM package has unexpected {name}"));
    }
    if header.entries.contains_key(&1047)
        && let Some(other) = header
            .strings(1047)?
            .into_iter()
            .find(|name| name != PACKAGE_NAME && !name.starts_with("rustleaks("))
    {
        return Err(format!("RPM package provides {other:?}"));
    }
    for (tag, name) in [(1039, "user"), (1040, "group")] {
        if header.strings(tag)?.iter().any(|owner| owner != "root") {
            return Err(format!("RPM package has a file {name} other than root"));
        }
    }
    if header.entries.contains_key(&5010) && header.strings(5010)?.iter().any(|cap| !cap.is_empty())
    {
        return Err("RPM package gives files capabilities".into());
    }
    let table = rpm_file_table(&header)?;
    let payload = gunzip(&bytes[payload_start..], MAX_PAYLOAD_BYTES)?;
    let observed = read_cpio(&payload)?;
    // rpm applies the header's modes and flags, so they must agree with the
    // payload that the content check reads.
    let payload_modes = observed
        .files
        .iter()
        .map(|(path, member)| (path.clone(), 0o100_000 | member.mode))
        .chain(
            observed
                .directories
                .iter()
                .map(|(path, mode)| (path.clone(), 0o040_000 | mode)),
        )
        .collect::<BTreeMap<_, _>>();
    let header_modes = table
        .iter()
        .map(|(path, (mode, _))| (path.clone(), *mode))
        .collect::<BTreeMap<_, _>>();
    if header_modes != payload_modes {
        return Err("RPM header file table differs from its payload".into());
    }
    if let Some((path, _)) = table
        .iter()
        .find(|(_, (_, flags))| flags & !(RPMFILE_DOC | RPMFILE_LICENSE) != 0)
    {
        return Err(format!(
            "RPM file {path:?} is marked as config, ghost or another special file"
        ));
    }
    contents.check(&observed, "RPM package")
}

/// Reads the header file table into path, mode and flags.
fn rpm_file_table(header: &RpmHeader<'_>) -> Result<BTreeMap<String, (u32, u32)>, String> {
    let basenames = header.strings(1117)?;
    let dirnames = header.strings(1118)?;
    let dirindexes = header.integers(1116, 4)?;
    let modes = header.integers(1030, 2)?;
    let flags = header.integers(1037, 4)?;
    if [dirindexes.len(), modes.len(), flags.len()]
        .iter()
        .any(|count| *count != basenames.len())
    {
        return Err("RPM header file table has arrays of different lengths".into());
    }
    let mut table = BTreeMap::new();
    for (index, basename) in basenames.iter().enumerate() {
        let directory = usize::try_from(dirindexes[index])
            .ok()
            .and_then(|directory| dirnames.get(directory))
            .ok_or("RPM header file table has a bad directory index")?;
        let path = normalized_path(
            format!("{directory}{basename}")
                .strip_prefix('/')
                .ok_or("RPM header file path is not absolute")?,
        )?;
        if table
            .insert(path.clone(), (modes[index], flags[index]))
            .is_some()
        {
            return Err(format!("RPM header lists {path:?} twice"));
        }
    }
    Ok(table)
}

impl Contents {
    fn check(&self, observed: &Observed, label: &str) -> Result<(), String> {
        if observed.files != self.files {
            let expected = self.files.keys().collect::<BTreeSet<_>>();
            let actual = observed.files.keys().collect::<BTreeSet<_>>();
            let missing = expected.difference(&actual).collect::<Vec<_>>();
            let extra = actual.difference(&expected).collect::<Vec<_>>();
            let changed = self
                .files
                .iter()
                .filter(|(path, member)| {
                    observed
                        .files
                        .get(*path)
                        .is_some_and(|seen| seen != *member)
                })
                .map(|(path, _)| path)
                .collect::<Vec<_>>();
            return Err(format!(
                "{label} files differ from the release archive: missing {missing:?}, extra {extra:?}, changed {changed:?}"
            ));
        }
        for (directory, mode) in &observed.directories {
            if !self.allowed_directories.contains(directory) || *mode != 0o755 {
                return Err(format!(
                    "{label} has unexpected directory {directory:?} with mode {mode:o}"
                ));
            }
        }
        if let Some(missing) = self
            .required_directories
            .iter()
            .find(|directory| !observed.directories.contains_key(*directory))
        {
            return Err(format!("{label} does not own directory {missing:?}"));
        }
        Ok(())
    }
}

impl Observed {
    fn insert_file(&mut self, path: String, member: Member) -> Result<(), String> {
        self.check_limit()?;
        if self.directories.contains_key(&path) || self.files.insert(path.clone(), member).is_some()
        {
            return Err(format!("package has duplicate entry {path:?}"));
        }
        Ok(())
    }

    fn insert_directory(&mut self, path: String, mode: u32) -> Result<(), String> {
        self.check_limit()?;
        if self.files.contains_key(&path) || self.directories.insert(path.clone(), mode).is_some() {
            return Err(format!("package has duplicate entry {path:?}"));
        }
        Ok(())
    }

    fn check_limit(&self) -> Result<(), String> {
        if self.files.len() + self.directories.len() >= MAX_ENTRIES {
            return Err("package exceeds its entry limit".into());
        }
        Ok(())
    }
}

fn read_package(path: &Path) -> Result<Vec<u8>, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("cannot inspect package {}: {error}", path.display()))?
        .len();
    if size > MAX_PACKAGE_BYTES {
        return Err(format!("package {} exceeds its size limit", path.display()));
    }
    fs::read(path).map_err(|error| format!("cannot read package {}: {error}", path.display()))
}

/// Decompresses one gzip stream that must fill `bytes` exactly. dpkg and
/// rpm read concatenated streams, so a byte after the first stream could
/// hold content that this check would not see.
fn gunzip(bytes: &[u8], limit: u64) -> Result<Vec<u8>, String> {
    // The `bufread` decoder reads from the slice itself, so the slice left
    // after the stream is exactly the input that it did not use.
    let mut decoder = GzDecoder::new(bytes);
    let mut output = Vec::new();
    (&mut decoder)
        .take(limit + 1)
        .read_to_end(&mut output)
        .map_err(|error| format!("cannot decompress package data: {error}"))?;
    if output.len() as u64 > limit {
        return Err("package data exceeds its decompressed size limit".into());
    }
    let rest = decoder.into_inner();
    if !rest.is_empty() {
        return Err("package data has bytes after its gzip stream".into());
    }
    Ok(output)
}

/// Python's `tarfile`, which `rules_pkg` uses, pads an archive with zeros to
/// a multiple of this record size after the two end blocks.
const TAR_RECORD_SIZE: usize = 20 * 512;

/// Requires that a tar archive ends with its two zero end blocks, followed
/// only by zero record padding. `consumed` is the length that the tar reader
/// used, up to and including the first zero block. The reader also stops
/// without error at the end of its input, so an archive without end blocks
/// needs this check.
fn check_tar_end(bytes: &[u8], consumed: usize) -> Result<(), String> {
    let tail = consumed
        .checked_sub(512)
        .and_then(|start| bytes.get(start..))
        .ok_or("package tar has no end-of-archive blocks")?;
    if tail.len() < 1024
        || tail.len() >= 1024 + TAR_RECORD_SIZE
        || !tail.len().is_multiple_of(512)
        || tail.iter().any(|byte| *byte != 0)
    {
        return Err("package tar lacks its end-of-archive blocks or has data after them".into());
    }
    Ok(())
}

/// Reads a common `ar` archive, the container format of a Debian package.
fn ar_members(bytes: &[u8]) -> Result<Vec<(&str, &[u8])>, String> {
    let mut rest = bytes
        .strip_prefix(b"!<arch>\n")
        .ok_or("Debian package is not an ar archive")?;
    let mut members = Vec::new();
    while !rest.is_empty() {
        if members.len() >= 3 {
            return Err("Debian package has more than three members".into());
        }
        if rest.len() < 60 || &rest[58..60] != b"`\n" {
            return Err("Debian package has a truncated ar member header".into());
        }
        let name = std::str::from_utf8(&rest[..16])
            .map_err(|_| "Debian package member name is not UTF-8")?
            .trim_end_matches(' ');
        let name = name.strip_suffix('/').unwrap_or(name);
        let size = std::str::from_utf8(&rest[48..58])
            .ok()
            .and_then(|size| size.trim_end_matches(' ').parse::<usize>().ok())
            .ok_or("Debian package member size is not a number")?;
        let end = 60_usize
            .checked_add(size)
            .filter(|end| *end <= rest.len())
            .ok_or("Debian package member is truncated")?;
        members.push((name, &rest[60..end]));
        let padded = end + (size % 2);
        rest = rest
            .get(padded..)
            .ok_or("Debian package member padding is truncated")?;
    }
    Ok(members)
}

fn normalized_path(raw: &str) -> Result<String, String> {
    let path = raw.strip_prefix("./").unwrap_or(raw);
    let path = if path == "." { "" } else { path };
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.starts_with('/')
        || path
            .split('/')
            .any(|part| part == "." || part == ".." || (part.is_empty() && !path.is_empty()))
    {
        return Err(format!("package path {raw:?} is not a plain relative path"));
    }
    Ok(path.to_owned())
}

fn read_tar(bytes: &[u8], observed: &mut Observed) -> Result<(), String> {
    let mut archive = tar::Archive::new(bytes);
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot read package tar: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("cannot read package tar entry: {error}"))?;
        let header = entry.header();
        let raw = entry
            .path()
            .map_err(|error| format!("package tar path is invalid: {error}"))?
            .to_str()
            .ok_or("package tar path is not UTF-8")?
            .to_owned();
        let path = normalized_path(&raw)?;
        if header.uid().map_err(|error| error.to_string())? != 0
            || header.gid().map_err(|error| error.to_string())? != 0
            || !matches!(header.username().ok().flatten(), None | Some("" | "root"))
            || !matches!(header.groupname().ok().flatten(), None | Some("" | "root"))
        {
            return Err(format!("package entry {path:?} is not owned by root"));
        }
        let mode = header.mode().map_err(|error| error.to_string())? & 0o7777;
        let kind = header.entry_type();
        if kind.is_dir() {
            observed.insert_directory(path, mode)?;
        } else if kind.is_file() {
            let size = entry.size();
            let sha256 = hash_reader(&mut entry, size)?;
            observed.insert_file(path, Member { size, sha256, mode })?;
        } else {
            return Err(format!("package entry {path:?} is not a file or directory"));
        }
    }
    let rest = archive.into_inner();
    check_tar_end(bytes, bytes.len() - rest.len())
}

fn read_tar_file(bytes: &[u8], wanted: &str) -> Result<String, String> {
    let mut archive = tar::Archive::new(bytes);
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot read package tar: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("cannot read package tar entry: {error}"))?;
        let raw = entry
            .path()
            .map_err(|error| error.to_string())?
            .to_str()
            .ok_or("package tar path is not UTF-8")?
            .to_owned();
        if normalized_path(&raw)? == wanted && entry.header().entry_type().is_file() {
            let mut text = String::new();
            entry
                .read_to_string(&mut text)
                .map_err(|error| format!("cannot read {wanted}: {error}"))?;
            return Ok(text);
        }
    }
    Err(format!("package tar has no {wanted}"))
}

fn hash_reader(reader: &mut impl Read, size: u64) -> Result<String, String> {
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read package entry: {error}"))?;
        if read == 0 {
            break;
        }
        count += read as u64;
        digest.update(&buffer[..read]);
    }
    if count != size {
        return Err("package entry is shorter or longer than its header size".into());
    }
    Ok(hex_lower(&digest.finalize()))
}

/// Parses a Debian control file into fields. Continuation lines join the
/// field before them.
fn control_fields(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let field = current
                .as_ref()
                .ok_or("Debian control starts with a continuation line")?;
            let value: &mut String = fields
                .get_mut(field)
                .ok_or("Debian control continuation has no field")?;
            value.push('\n');
            value.push_str(line.trim_start());
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("Debian control line {line:?} has no field name"))?;
        if fields
            .insert(name.to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("Debian control repeats field {name}"));
        }
        current = Some(name.to_owned());
    }
    Ok(fields)
}

struct RpmHeader<'a> {
    entries: BTreeMap<u32, (u32, usize, usize)>,
    store: &'a [u8],
}

/// Reads an RPM header structure at `offset` and returns it with its end.
fn rpm_header(bytes: &[u8], offset: usize) -> Result<(RpmHeader<'_>, usize), String> {
    let intro = bytes
        .get(offset..offset + 16)
        .ok_or("RPM header is truncated")?;
    if intro[..4] != [0x8e, 0xad, 0xe8, 0x01] {
        return Err("RPM header has the wrong magic".into());
    }
    let count = be_u32(&intro[8..12]) as usize;
    let size = be_u32(&intro[12..16]) as usize;
    if count > MAX_ENTRIES * 8 {
        return Err("RPM header has too many entries".into());
    }
    let index_start = offset + 16;
    let store_start = count
        .checked_mul(16)
        .and_then(|length| index_start.checked_add(length))
        .ok_or("RPM header index overflow")?;
    let end = store_start
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or("RPM header store is truncated")?;
    let store = &bytes[store_start..end];
    let mut entries = BTreeMap::new();
    for index in 0..count {
        let entry = &bytes[index_start + index * 16..index_start + index * 16 + 16];
        let tag = be_u32(&entry[..4]);
        let kind = be_u32(&entry[4..8]);
        let data = be_u32(&entry[8..12]) as usize;
        let items = be_u32(&entry[12..16]) as usize;
        if data > store.len() {
            return Err(format!("RPM header tag {tag} points outside its store"));
        }
        if entries.insert(tag, (kind, data, items)).is_some() {
            return Err(format!("RPM header repeats tag {tag}"));
        }
    }
    Ok((RpmHeader { entries, store }, end))
}

impl RpmHeader<'_> {
    fn string(&self, tag: u32) -> Result<String, String> {
        let (kind, offset, count) = self
            .entries
            .get(&tag)
            .ok_or_else(|| format!("RPM header has no tag {tag}"))?;
        if *kind != 6 || *count != 1 {
            return Err(format!("RPM header tag {tag} is not one string"));
        }
        Ok(self.c_strings(*offset, 1)?.remove(0))
    }

    fn strings(&self, tag: u32) -> Result<Vec<String>, String> {
        let (kind, offset, count) = self
            .entries
            .get(&tag)
            .ok_or_else(|| format!("RPM header has no tag {tag}"))?;
        if *kind != 8 {
            return Err(format!("RPM header tag {tag} is not a string array"));
        }
        self.c_strings(*offset, *count)
    }

    /// Reads an INT16 (`size` 2) or INT32 (`size` 4) array.
    fn integers(&self, tag: u32, size: usize) -> Result<Vec<u32>, String> {
        let (kind, offset, count) = self
            .entries
            .get(&tag)
            .ok_or_else(|| format!("RPM header has no tag {tag}"))?;
        let expected = if size == 2 { 3 } else { 4 };
        if *kind != expected {
            return Err(format!(
                "RPM header tag {tag} has type {kind}, expected {expected}"
            ));
        }
        let end = count
            .checked_mul(size)
            .and_then(|length| offset.checked_add(length))
            .filter(|end| *end <= self.store.len())
            .ok_or_else(|| format!("RPM header tag {tag} runs past its store"))?;
        Ok(self.store[*offset..end]
            .chunks_exact(size)
            .map(|chunk| {
                if size == 2 {
                    u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
                } else {
                    be_u32(chunk)
                }
            })
            .collect())
    }

    fn c_strings(&self, offset: usize, count: usize) -> Result<Vec<String>, String> {
        let mut values = Vec::with_capacity(count.min(MAX_ENTRIES));
        let mut rest = &self.store[offset..];
        for _ in 0..count {
            let end = rest
                .iter()
                .position(|byte| *byte == 0)
                .ok_or("RPM header string is not NUL-terminated")?;
            values.push(
                std::str::from_utf8(&rest[..end])
                    .map_err(|_| "RPM header string is not UTF-8")?
                    .to_owned(),
            );
            rest = &rest[end + 1..];
        }
        Ok(values)
    }
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Reads a `newc` cpio archive, the payload format of an RPM package.
fn read_cpio(bytes: &[u8]) -> Result<Observed, String> {
    let mut observed = Observed::default();
    let mut offset = 0_usize;
    loop {
        let header = bytes
            .get(offset..offset + 110)
            .ok_or("RPM payload has a truncated cpio header")?;
        if &header[..6] != b"070701" {
            return Err("RPM payload is not a newc cpio archive".into());
        }
        let field = |index: usize| -> Result<u64, String> {
            let start = 6 + index * 8;
            std::str::from_utf8(&header[start..start + 8])
                .ok()
                .and_then(|text| u64::from_str_radix(text, 16).ok())
                .ok_or_else(|| "RPM payload cpio header has a bad number".to_owned())
        };
        let mode = u32::try_from(field(1)?).map_err(|_| "RPM payload mode is too large")?;
        let uid = field(2)?;
        let gid = field(3)?;
        let size = field(6)?;
        let name_size = usize::try_from(field(11)?).map_err(|_| "RPM payload name is too long")?;
        if name_size == 0 || name_size > 4096 {
            return Err("RPM payload has an empty or oversized path".into());
        }
        let name_start = offset + 110;
        let name_bytes = bytes
            .get(name_start..name_start + name_size)
            .ok_or("RPM payload path is truncated")?;
        let (last, name) = name_bytes.split_last().ok_or("RPM payload path is empty")?;
        if *last != 0 {
            return Err("RPM payload path is not NUL-terminated".into());
        }
        let name = std::str::from_utf8(name).map_err(|_| "RPM payload path is not UTF-8")?;
        let data_start = (name_start + name_size).next_multiple_of(4);
        if name == "TRAILER!!!" {
            // rpm stops at the trailer, so only short zero block padding
            // may follow it.
            let rest = bytes.get(data_start..).unwrap_or_default();
            if rest.len() >= 512 || rest.iter().any(|byte| *byte != 0) {
                return Err("RPM payload has data after its cpio trailer".into());
            }
            return Ok(observed);
        }
        let size_usize = usize::try_from(size).map_err(|_| "RPM payload entry is too large")?;
        let data = bytes
            .get(data_start..data_start + size_usize)
            .ok_or("RPM payload entry is truncated")?;
        let path = normalized_path(name)?;
        if uid != 0 || gid != 0 {
            return Err(format!("RPM payload entry {path:?} is not owned by root"));
        }
        let permissions = mode & 0o7777;
        match mode & 0o170000 {
            0o040000 => {
                if size != 0 {
                    return Err(format!("RPM payload directory {path:?} has data"));
                }
                observed.insert_directory(path, permissions)?;
            }
            0o100000 => observed.insert_file(
                path,
                Member {
                    size,
                    sha256: sha256_bytes(data),
                    mode: permissions,
                },
            )?,
            _ => {
                return Err(format!(
                    "RPM payload entry {path:?} is not a file or directory"
                ));
            }
        }
        offset = (data_start + size_usize).next_multiple_of(4);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::BTreeMap;
    use std::io::Write as _;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::{contents, identity, package_version, verify_deb, verify_rpm, write_input};
    use crate::tooling::{ScopedTempDir, sha256_bytes};

    pub(in super::super) struct PackageFile {
        pub(in super::super) path: String,
        pub(in super::super) bytes: Vec<u8>,
        pub(in super::super) mode: u32,
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn tar(entries: &[(String, Option<&[u8]>, u32)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(*mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_username("root").unwrap();
            header.set_groupname("root").unwrap();
            header.set_mtime(946_684_800);
            if let Some(bytes) = bytes {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(bytes.len() as u64);
                builder.append_data(&mut header, path, *bytes).unwrap();
            } else {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                builder.append_data(&mut header, path, &[][..]).unwrap();
            }
        }
        builder.into_inner().unwrap()
    }

    fn ar(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut output = b"!<arch>\n".to_vec();
        for (name, bytes) in members {
            writeln!(
                output,
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`",
                format!("{name}/"),
                0,
                0,
                0,
                "100644",
                bytes.len()
            )
            .unwrap();
            output.extend_from_slice(bytes);
            if !bytes.len().is_multiple_of(2) {
                output.push(b'\n');
            }
        }
        output
    }

    fn tar_entries<'a>(
        files: &'a [PackageFile],
        directories: &[&str],
    ) -> Vec<(String, Option<&'a [u8]>, u32)> {
        let mut entries = directories
            .iter()
            .map(|directory| ((*directory).to_owned(), None, 0o755))
            .collect::<Vec<_>>();
        entries.extend(
            files
                .iter()
                .map(|file| (file.path.clone(), Some(file.bytes.as_slice()), file.mode)),
        );
        entries
    }

    /// Builds a Debian package with the given compressed data member.
    fn deb_with_data(control: &str, data: Vec<u8>) -> Vec<u8> {
        let control_tar = tar(&[("./control".to_owned(), Some(control.as_bytes()), 0o644)]);
        ar(&[
            ("debian-binary", b"2.0\n".to_vec()),
            ("control.tar.gz", gzip(&control_tar)),
            ("data.tar.gz", data),
        ])
    }

    /// Builds a Debian package shaped like the `pkg_deb` output.
    pub(in super::super) fn synthetic_deb(
        files: &[PackageFile],
        directories: &[&str],
        control: &str,
    ) -> Vec<u8> {
        deb_with_data(control, gzip(&tar(&tar_entries(files, directories))))
    }

    /// One synthetic RPM header tag: strings (type 6 or 8) or integers
    /// (type 3 or 4).
    #[derive(Clone)]
    pub(in super::super) enum Tag {
        Strings(u32, u32, Vec<String>),
        Integers(u32, u32, Vec<u32>),
    }

    fn rpm_store(tags: &[Tag]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut store = Vec::new();
        for tag in tags {
            let (number, kind, count) = match tag {
                Tag::Strings(number, kind, values) => (number, kind, values.len()),
                Tag::Integers(number, kind, values) => (number, kind, values.len()),
            };
            if *kind == 4 {
                while !store.len().is_multiple_of(4) {
                    store.push(0);
                }
            }
            index.extend_from_slice(&number.to_be_bytes());
            index.extend_from_slice(&kind.to_be_bytes());
            index.extend_from_slice(&u32::try_from(store.len()).unwrap().to_be_bytes());
            index.extend_from_slice(&u32::try_from(count).unwrap().to_be_bytes());
            match tag {
                Tag::Strings(_, _, values) => {
                    for value in values {
                        store.extend_from_slice(value.as_bytes());
                        store.push(0);
                    }
                }
                Tag::Integers(_, 3, values) => {
                    for value in values {
                        store.extend_from_slice(&u16::try_from(*value).unwrap().to_be_bytes());
                    }
                }
                Tag::Integers(_, _, values) => {
                    for value in values {
                        store.extend_from_slice(&value.to_be_bytes());
                    }
                }
            }
        }
        let mut header = vec![0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
        header.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_be_bytes());
        header.extend_from_slice(&u32::try_from(store.len()).unwrap().to_be_bytes());
        header.extend_from_slice(&index);
        header.extend_from_slice(&store);
        header
    }

    fn cpio(entries: &[(String, Option<&[u8]>, u32)]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut write_entry = |name: &str, bytes: &[u8], mode: u32| {
            let name_size = name.len() + 1;
            write!(
                output,
                "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                1,
                mode,
                0,
                0,
                1,
                0,
                bytes.len(),
                0,
                0,
                0,
                0,
                name_size,
                0
            )
            .unwrap();
            output.extend_from_slice(name.as_bytes());
            output.push(0);
            while !output.len().is_multiple_of(4) {
                output.push(0);
            }
            output.extend_from_slice(bytes);
            while !output.len().is_multiple_of(4) {
                output.push(0);
            }
        };
        for (path, bytes, mode) in entries {
            match bytes {
                Some(bytes) => write_entry(&format!("./{path}"), bytes, 0o100000 | mode),
                None => write_entry(&format!("./{path}"), &[], 0o040000 | mode),
            }
        }
        write_entry("TRAILER!!!", &[], 0);
        output
    }

    /// Builds an RPM package with the tags and payload that the verifier
    /// reads, shaped like the `pkg_rpm` output.
    pub(in super::super) fn synthetic_rpm(
        files: &[PackageFile],
        directories: &[&str],
        version: &str,
        architecture: &str,
        extra_tags: &[Tag],
    ) -> Vec<u8> {
        let entries = tar_entries(files, directories);
        let owners = vec!["root".to_owned(); entries.len()];
        let mut dirnames = Vec::<String>::new();
        let mut dirindexes = Vec::new();
        let mut basenames = Vec::new();
        let mut modes = Vec::new();
        for (path, bytes, mode) in &entries {
            let (directory, basename) = path.rsplit_once('/').unwrap();
            let directory = format!("/{directory}/");
            let index = dirnames
                .iter()
                .position(|name| *name == directory)
                .unwrap_or_else(|| {
                    dirnames.push(directory.clone());
                    dirnames.len() - 1
                });
            dirindexes.push(u32::try_from(index).unwrap());
            basenames.push(basename.to_owned());
            modes.push(
                if bytes.is_some() {
                    0o100_000
                } else {
                    0o040_000
                } | mode,
            );
        }
        let mut tags = vec![
            Tag::Strings(1000, 6, vec!["rustleaks".to_owned()]),
            Tag::Strings(1001, 6, vec![version.to_owned()]),
            Tag::Strings(1002, 6, vec!["1".to_owned()]),
            Tag::Strings(1022, 6, vec![architecture.to_owned()]),
            Tag::Integers(1030, 3, modes),
            Tag::Integers(1037, 4, vec![2; entries.len()]),
            Tag::Strings(1039, 8, owners.clone()),
            Tag::Strings(1040, 8, owners),
            Tag::Strings(
                1047,
                8,
                vec!["rustleaks".to_owned(), "rustleaks(x86-64)".to_owned()],
            ),
            Tag::Integers(1116, 4, dirindexes),
            Tag::Strings(1117, 8, basenames),
            Tag::Strings(1118, 8, dirnames),
            Tag::Strings(1124, 6, vec!["cpio".to_owned()]),
            Tag::Strings(1125, 6, vec!["gzip".to_owned()]),
        ];
        for extra in extra_tags {
            let number = match extra {
                Tag::Strings(number, ..) | Tag::Integers(number, ..) => *number,
            };
            tags.retain(
                |tag| !matches!(tag, Tag::Strings(n, ..) | Tag::Integers(n, ..) if *n == number),
            );
            tags.push(extra.clone());
        }
        let mut output = vec![0_u8; 96];
        output[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        output[4] = 3;
        output.extend_from_slice(&rpm_store(&[Tag::Strings(1000, 7, vec!["sig".to_owned()])]));
        while !output.len().is_multiple_of(8) {
            output.push(0);
        }
        output.extend_from_slice(&rpm_store(&tags));
        output.extend_from_slice(&gzip(&cpio(&entries)));
        output
    }

    fn documents() -> BTreeMap<String, (Vec<u8>, u32)> {
        [
            "LICENSE",
            "NOTICE",
            "README.md",
            "licenses/index.json",
            "licenses/packages/example/LICENSE-MIT",
        ]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                (format!("synthetic bytes for {name}\n").into_bytes(), 0o644),
            )
        })
        .collect()
    }

    pub(in super::super) fn package_files(
        documents: &BTreeMap<String, (Vec<u8>, u32)>,
        binary: &[u8],
    ) -> Vec<PackageFile> {
        let mut files = vec![PackageFile {
            path: "usr/bin/rustleaks".into(),
            bytes: binary.to_vec(),
            mode: 0o755,
        }];
        files.extend(documents.iter().map(|(name, (bytes, _))| PackageFile {
            path: format!("usr/share/doc/rustleaks/{name}"),
            bytes: bytes.clone(),
            mode: 0o644,
        }));
        files
    }

    pub(in super::super) const DOC_DIRECTORIES: &[&str] = &[
        "usr/share/doc/rustleaks",
        "usr/share/doc/rustleaks/licenses",
        "usr/share/doc/rustleaks/licenses/packages",
        "usr/share/doc/rustleaks/licenses/packages/example",
    ];

    pub(in super::super) fn deb_control(
        version: &str,
        architecture: &str,
        depends: &str,
    ) -> String {
        format!(
            "Package: rustleaks\nVersion: {version}\nSection: devel\nArchitecture: {architecture}\nDepends: {depends}\nDescription: Secret scanner.\n More text.\n"
        )
    }

    #[test]
    fn package_versions_sort_prereleases_first() {
        assert_eq!(package_version("0.2.0"), "0.2.0");
        assert_eq!(package_version("0.2.0-alpha.12"), "0.2.0~alpha.12");
        let arm = identity("aarch64-unknown-linux-gnu", "0.2.0-rc.1", "GLIBC_2.28").unwrap();
        assert_eq!(arm.version, "0.2.0~rc.1");
        assert_eq!(arm.deb_architecture, "arm64");
        assert_eq!(arm.rpm_architecture, "aarch64");
        assert_eq!(arm.depends, "libc6 (>= 2.28)");
        assert!(identity("x86_64-unknown-linux-musl", "0.2.0", "GLIBC_2.28").is_err());
        assert!(identity("x86_64-unknown-linux-gnu", "0.2.0", "none").is_err());
        assert!(identity("x86_64-unknown-linux-gnu", "0.2.0", "GLIBC_2..28").is_err());
    }

    #[test]
    fn packages_must_install_exactly_the_archive_files() {
        let root = ScopedTempDir::new("linux-package-contents").unwrap();
        let documents = documents();
        let binary = b"synthetic release binary".to_vec();
        let expected = contents(&documents, &sha256_bytes(&binary), binary.len() as u64).unwrap();
        let identity = identity("x86_64-unknown-linux-gnu", "0.2.0-alpha.1", "GLIBC_2.28").unwrap();
        let control = deb_control("0.2.0~alpha.1", "amd64", "libc6 (>= 2.28)");
        let mut deb_directories = vec!["usr", "usr/bin", "usr/share", "usr/share/doc"];
        deb_directories.extend_from_slice(DOC_DIRECTORIES);
        let files = package_files(&documents, &binary);
        let deb = root.path.join("rustleaks.deb");
        let rpm = root.path.join("rustleaks.rpm");

        std::fs::write(&deb, synthetic_deb(&files, &deb_directories, &control)).unwrap();
        verify_deb(&deb, &expected, &identity).unwrap();
        std::fs::write(
            &rpm,
            synthetic_rpm(&files, DOC_DIRECTORIES, "0.2.0~alpha.1", "x86_64", &[]),
        )
        .unwrap();
        verify_rpm(&rpm, &expected, &identity).unwrap();

        // A changed binary, a missing or extra document, a changed mode and
        // a missing owned directory are each rejected.
        let mut changed = package_files(&documents, b"other binary bytes");
        std::fs::write(&deb, synthetic_deb(&changed, &deb_directories, &control)).unwrap();
        assert!(verify_deb(&deb, &expected, &identity).is_err());
        std::fs::write(
            &rpm,
            synthetic_rpm(&changed, DOC_DIRECTORIES, "0.2.0~alpha.1", "x86_64", &[]),
        )
        .unwrap();
        assert!(verify_rpm(&rpm, &expected, &identity).is_err());

        changed = package_files(&documents, &binary);
        changed.pop();
        std::fs::write(&deb, synthetic_deb(&changed, &deb_directories, &control)).unwrap();
        assert!(verify_deb(&deb, &expected, &identity).is_err());

        changed = package_files(&documents, &binary);
        changed.push(super::tests::PackageFile {
            path: "etc/rustleaks.toml".into(),
            bytes: b"extra".to_vec(),
            mode: 0o644,
        });
        std::fs::write(
            &rpm,
            synthetic_rpm(&changed, DOC_DIRECTORIES, "0.2.0~alpha.1", "x86_64", &[]),
        )
        .unwrap();
        assert!(verify_rpm(&rpm, &expected, &identity).is_err());

        changed = package_files(&documents, &binary);
        changed[0].mode = 0o4755;
        std::fs::write(&deb, synthetic_deb(&changed, &deb_directories, &control)).unwrap();
        assert!(verify_deb(&deb, &expected, &identity).is_err());

        std::fs::write(
            &rpm,
            synthetic_rpm(
                &files,
                &DOC_DIRECTORIES[..1],
                "0.2.0~alpha.1",
                "x86_64",
                &[],
            ),
        )
        .unwrap();
        assert!(verify_rpm(&rpm, &expected, &identity).is_err());
        std::fs::write(&deb, synthetic_deb(&files, &["usr", "etc"], &control)).unwrap();
        assert!(verify_deb(&deb, &expected, &identity).is_err());
    }

    #[test]
    fn packages_must_carry_the_release_identity_and_no_scripts() {
        let root = ScopedTempDir::new("linux-package-identity").unwrap();
        let documents = documents();
        let binary = b"synthetic release binary".to_vec();
        let expected = contents(&documents, &sha256_bytes(&binary), binary.len() as u64).unwrap();
        let identity = identity("x86_64-unknown-linux-gnu", "0.2.0", "GLIBC_2.28").unwrap();
        let files = package_files(&documents, &binary);
        let deb = root.path.join("rustleaks.deb");
        let rpm = root.path.join("rustleaks.rpm");

        for control in [
            deb_control("0.1.9", "amd64", "libc6 (>= 2.28)"),
            deb_control("0.2.0", "arm64", "libc6 (>= 2.28)"),
            deb_control("0.2.0", "amd64", "libc6 (>= 2.17)"),
            deb_control("0.2.0", "amd64", "libc6 (>= 2.28)") + "Pre-Depends: dpkg\n",
        ] {
            std::fs::write(&deb, synthetic_deb(&files, DOC_DIRECTORIES, &control)).unwrap();
            assert!(
                verify_deb(&deb, &expected, &identity).is_err(),
                "accepted {control}"
            );
        }
        std::fs::write(
            &deb,
            synthetic_deb(
                &files,
                DOC_DIRECTORIES,
                &deb_control("0.2.0", "amd64", "libc6 (>= 2.28)"),
            ),
        )
        .unwrap();
        verify_deb(&deb, &expected, &identity).unwrap();

        let file_count = files.len() + DOC_DIRECTORIES.len();
        for (version, architecture, extra) in [
            ("0.2.0~rc.1", "x86_64", vec![]),
            ("0.2.0", "aarch64", vec![]),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(1024, 6, vec!["rm -rf /".to_owned()])],
            ),
            // A post-install interpreter with no script body still runs.
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(1086, 8, vec!["/sbin/ldconfig".to_owned()])],
            ),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(1151, 6, vec!["true".to_owned()])],
            ),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(5066, 8, vec!["true".to_owned()])],
            ),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(1054, 8, vec!["gitleaks".to_owned()])],
            ),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(1090, 8, vec!["gitleaks".to_owned()])],
            ),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(1047, 8, vec!["gitleaks".to_owned()])],
            ),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Strings(
                    5010,
                    8,
                    vec!["cap_net_raw=ep".to_owned(); file_count],
                )],
            ),
            // The header gives the binary setuid while the payload does not.
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Integers(1030, 3, {
                    let mut modes = vec![0o040_755; DOC_DIRECTORIES.len()];
                    modes.push(0o104_755);
                    modes.extend(std::iter::repeat_n(0o100_644, files.len() - 1));
                    modes
                })],
            ),
            // A config or ghost flag on the files.
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Integers(1037, 4, vec![1; file_count])],
            ),
            (
                "0.2.0",
                "x86_64",
                vec![Tag::Integers(1037, 4, vec![64; file_count])],
            ),
        ] {
            std::fs::write(
                &rpm,
                synthetic_rpm(&files, DOC_DIRECTORIES, version, architecture, &extra),
            )
            .unwrap();
            assert!(verify_rpm(&rpm, &expected, &identity).is_err());
        }
        std::fs::write(
            &rpm,
            synthetic_rpm(&files, DOC_DIRECTORIES, "0.2.0", "x86_64", &[]),
        )
        .unwrap();
        verify_rpm(&rpm, &expected, &identity).unwrap();
        let mut truncated = std::fs::read(&rpm).unwrap();
        truncated.truncate(truncated.len() - 9);
        std::fs::write(&rpm, truncated).unwrap();
        assert!(verify_rpm(&rpm, &expected, &identity).is_err());
    }

    #[test]
    fn package_input_holds_the_binary_documents_and_dependency() {
        let root = ScopedTempDir::new("linux-package-input").unwrap();
        let documents = documents();
        let identity = identity("x86_64-unknown-linux-gnu", "0.2.0", "GLIBC_2.28").unwrap();
        let output = root.path.join("input");
        write_input(&output, &documents, b"binary", &identity).unwrap();
        assert_eq!(std::fs::read(output.join("rustleaks")).unwrap(), b"binary");
        assert_eq!(
            std::fs::read_to_string(output.join("depends.txt")).unwrap(),
            "libc6 (>= 2.28)\n"
        );
        for (name, (bytes, _)) in &documents {
            assert_eq!(
                &std::fs::read(output.join("doc").join(name)).unwrap(),
                bytes
            );
        }
        assert!(write_input(&output, &documents, b"binary", &identity).is_err());
    }

    #[test]
    fn packages_must_not_hide_data_after_the_checked_content() {
        let root = ScopedTempDir::new("linux-package-trailing").unwrap();
        let documents = documents();
        let binary = b"synthetic release binary".to_vec();
        let expected = contents(&documents, &sha256_bytes(&binary), binary.len() as u64).unwrap();
        let identity = identity("x86_64-unknown-linux-gnu", "0.2.0", "GLIBC_2.28").unwrap();
        let control = deb_control("0.2.0", "amd64", "libc6 (>= 2.28)");
        let files = package_files(&documents, &binary);
        let data_tar = tar(&tar_entries(&files, DOC_DIRECTORIES));
        let extra_file = [PackageFile {
            path: "etc/rustleaks.toml".into(),
            bytes: b"extra".to_vec(),
            mode: 0o644,
        }];
        let extra_tar = tar(&tar_entries(&extra_file, &[]));
        let deb = root.path.join("rustleaks.deb");
        let check_deb = |data: Vec<u8>| {
            std::fs::write(&deb, deb_with_data(&control, data)).unwrap();
            verify_deb(&deb, &expected, &identity)
        };

        // Python's tarfile pads with zeros to its 10240-byte record size.
        let mut padded = data_tar.clone();
        padded.resize(data_tar.len().next_multiple_of(10_240), 0);
        check_deb(gzip(&padded)).unwrap();

        // dpkg decodes a second gzip stream after the first.
        let mut streams = gzip(&data_tar);
        streams.extend_from_slice(&gzip(&extra_tar));
        let error = check_deb(streams).unwrap_err();
        assert!(error.contains("after its gzip stream"), "{error}");
        let mut garbage = gzip(&data_tar);
        garbage.push(0);
        assert!(check_deb(garbage).is_err());

        // A tar reader stops cleanly at the end of its input, so the end
        // blocks must be present, and only zeros may follow them.
        for cut in [512, 1024] {
            let short = &data_tar[..data_tar.len() - cut];
            let error = check_deb(gzip(short)).unwrap_err();
            assert!(error.contains("end-of-archive"), "{error}");
        }
        let mut appended = data_tar.clone();
        appended.extend_from_slice(&extra_tar);
        let error = check_deb(gzip(&appended)).unwrap_err();
        assert!(error.contains("end-of-archive"), "{error}");
        let mut overlong = data_tar.clone();
        overlong.resize(data_tar.len() + 10_240, 0);
        assert!(check_deb(gzip(&overlong)).is_err());

        let rpm = root.path.join("rustleaks.rpm");
        let package = synthetic_rpm(&files, DOC_DIRECTORIES, "0.2.0", "x86_64", &[]);
        let payload = cpio(&tar_entries(&files, DOC_DIRECTORIES));
        let lead = &package[..package.len() - gzip(&payload).len()];
        let check_rpm = |payload: Vec<u8>| {
            std::fs::write(&rpm, [lead, payload.as_slice()].concat()).unwrap();
            verify_rpm(&rpm, &expected, &identity)
        };
        check_rpm(gzip(&payload)).unwrap();
        let mut streams = gzip(&payload);
        streams.extend_from_slice(&gzip(&cpio(&tar_entries(&extra_file, &[]))));
        let error = check_rpm(streams).unwrap_err();
        assert!(error.contains("after its gzip stream"), "{error}");
        let mut padded = payload.clone();
        padded.resize(payload.len().next_multiple_of(512), 0);
        check_rpm(gzip(&padded)).unwrap();
        let mut appended = payload.clone();
        appended.extend_from_slice(b"extra");
        let error = check_rpm(gzip(&appended)).unwrap_err();
        assert!(error.contains("after its cpio trailer"), "{error}");
    }
}
