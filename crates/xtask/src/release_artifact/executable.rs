//! Checks how a Linux or macOS release executable is linked.
//!
//! A GNU executable must be a dynamic PIE: ELF type `ET_DYN` with a program
//! interpreter. A musl executable must be static: no interpreter and no
//! needed shared library. The x86_64 musl executable must also be a static
//! PIE (`ET_DYN`). Rust's `aarch64-unknown-linux-musl` target links a static
//! executable that is not position independent, so that target may be
//! `ET_EXEC`. The toolchain decides all of this at link time, so a toolchain
//! change can turn a PIE into a fixed-address `ET_EXEC` with no other symptom.
//!
//! A macOS executable must be a thin 64-bit Mach-O `MH_EXECUTE` file for the
//! target's CPU with one `LC_UUID` load command. dyld on recent macOS
//! refuses to start an executable that is linked against a recent SDK and
//! has no UUID. The hosted macOS runners do not enforce that, so a release
//! binary without a UUID passes every smoke test there.

const ET_DYN: u16 = 3;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const PROGRAM_HEADER_SIZE: usize = 56;
const DYNAMIC_ENTRY_SIZE: usize = 16;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MACH_HEADER_SIZE: usize = 32;
const LOAD_COMMAND_SIZE: usize = 8;
const UUID_COMMAND_SIZE: u32 = 24;
const LC_UUID: u32 = 0x1b;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// The Mach-O file type of an executable.
const MH_EXECUTE: u32 = 2;
/// The Mach-O file type of a dynamic library.
pub(super) const MH_DYLIB: u32 = 6;

/// Checks the release executable `bytes` for `target`. Targets other than
/// Linux and macOS pass without a check.
pub(super) fn validate(target: &str, bytes: &[u8]) -> Result<(), String> {
    if target.ends_with("-apple-darwin") {
        return validate_mach_o(target, MH_EXECUTE, bytes);
    }
    let gnu = target.ends_with("-linux-gnu");
    if !gnu && !target.ends_with("-linux-musl") {
        return Ok(());
    }
    let elf = Elf::parse(bytes)?;
    let pie_required = target != "aarch64-unknown-linux-musl";
    if pie_required && elf.kind != ET_DYN {
        return Err(format!(
            "{target} executable has ELF type {}, not a position-independent ET_DYN",
            elf.kind
        ));
    }
    match (gnu, elf.interpreter, elf.needed) {
        (true, false, _) => Err(format!("{target} executable has no program interpreter")),
        (false, true, _) => Err(format!(
            "{target} executable is not static: it has a program interpreter"
        )),
        (false, false, true) => Err(format!(
            "{target} executable is not static: it needs a shared library"
        )),
        _ => Ok(()),
    }
}

/// Checks that `bytes` is a thin 64-bit little-endian Mach-O file of
/// `file_type` for the CPU of the Apple `target`, with one well-formed
/// `LC_UUID` load command.
pub(super) fn validate_mach_o(target: &str, file_type: u32, bytes: &[u8]) -> Result<(), String> {
    let cpu = match target {
        "x86_64-apple-darwin" => CPU_TYPE_X86_64,
        "aarch64-apple-darwin" => CPU_TYPE_ARM64,
        _ => return Err(format!("{target} is not a macOS release target")),
    };
    if bytes.get(..4) != Some(MH_MAGIC_64.to_le_bytes().as_slice()) {
        return Err(format!(
            "{target} binary is not a thin 64-bit little-endian Mach-O file"
        ));
    }
    if mach_u32_at(bytes, 4)? != cpu {
        return Err(format!("{target} binary is a Mach-O file for another CPU"));
    }
    let kind = mach_u32_at(bytes, 12)?;
    if kind != file_type {
        return Err(format!(
            "{target} binary has Mach-O file type {kind}, not {file_type}"
        ));
    }
    let count = mach_usize_at(bytes, 16)?;
    let end = mach_usize_at(bytes, 20)?
        .checked_add(MACH_HEADER_SIZE)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("{target} binary Mach-O load commands are out of bounds"))?;
    let mut offset = MACH_HEADER_SIZE;
    let mut uuids = 0_usize;
    for _ in 0..count {
        if end - offset < LOAD_COMMAND_SIZE {
            return Err(format!(
                "{target} binary Mach-O load commands are truncated"
            ));
        }
        let command = mach_u32_at(bytes, offset)?;
        let size = mach_usize_at(bytes, offset + 4)?;
        if size < LOAD_COMMAND_SIZE || size % 8 != 0 || size > end - offset {
            return Err(format!(
                "{target} binary has a Mach-O load command of invalid size {size}"
            ));
        }
        if command == LC_UUID {
            if mach_u32_at(bytes, offset + 4)? != UUID_COMMAND_SIZE {
                return Err(format!(
                    "{target} binary has an LC_UUID load command of size {size}"
                ));
            }
            uuids += 1;
        }
        offset += size;
    }
    match uuids {
        1 => Ok(()),
        0 => Err(format!(
            "{target} binary has no LC_UUID load command, so dyld refuses to load it"
        )),
        _ => Err(format!("{target} binary has {uuids} LC_UUID load commands")),
    }
}

fn mach_u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    offset
        .checked_add(4)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| "release binary Mach-O headers are truncated".to_owned())
}

fn mach_usize_at(bytes: &[u8], offset: usize) -> Result<usize, String> {
    usize::try_from(mach_u32_at(bytes, offset)?)
        .map_err(|_| "release binary Mach-O size does not fit in memory".to_owned())
}

struct Elf {
    kind: u16,
    interpreter: bool,
    needed: bool,
}

impl Elf {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.get(..4) != Some(b"\x7fELF".as_slice()) {
            return Err("release executable is not an ELF file".into());
        }
        if bytes.get(4..6) != Some([2, 1].as_slice()) {
            return Err("release executable is not a 64-bit little-endian ELF file".into());
        }
        let kind = u16_at(bytes, 16)?;
        let table = usize_at(bytes, 32)?;
        let entry_size = usize::from(u16_at(bytes, 54)?);
        let count = usize::from(u16_at(bytes, 56)?);
        if entry_size != PROGRAM_HEADER_SIZE {
            return Err("release executable has an unexpected program header size".into());
        }
        let mut interpreter = false;
        let mut needed = false;
        for index in 0..count {
            let header = index
                .checked_mul(PROGRAM_HEADER_SIZE)
                .and_then(|offset| offset.checked_add(table))
                .ok_or("release executable program header table overflows")?;
            match u32_at(bytes, header)? {
                PT_INTERP => interpreter = true,
                PT_DYNAMIC => {
                    let offset = usize_at(bytes, header + 8)?;
                    let size = usize_at(bytes, header + 32)?;
                    needed |= dynamic_needs_library(bytes, offset, size)?;
                }
                _ => {}
            }
        }
        Ok(Self {
            kind,
            interpreter,
            needed,
        })
    }
}

fn dynamic_needs_library(bytes: &[u8], offset: usize, size: usize) -> Result<bool, String> {
    let end = offset
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or("release executable dynamic section is out of bounds")?;
    for entry in (offset..end).step_by(DYNAMIC_ENTRY_SIZE) {
        match u64_at(bytes, entry)? {
            DT_NULL => break,
            DT_NEEDED => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], String> {
    offset
        .checked_add(N)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| "release executable ELF headers are truncated".to_owned())
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    field(bytes, offset).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    field(bytes, offset).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    field(bytes, offset).map(u64::from_le_bytes)
}

fn usize_at(bytes: &[u8], offset: usize) -> Result<usize, String> {
    usize::try_from(u64_at(bytes, offset)?)
        .map_err(|_| "release executable ELF offset does not fit in memory".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64 file with the given type, program headers and
    /// dynamic entries. Program headers are (type, offset, size) triples.
    fn elf(kind: u16, interpreter: bool, needed: bool) -> Vec<u8> {
        let mut headers = vec![(1_u32, 0_u64, 0_u64)];
        if interpreter {
            headers.push((PT_INTERP, 0, 0));
        }
        let dynamic_offset = 64 + PROGRAM_HEADER_SIZE * (headers.len() + 1);
        headers.push((
            PT_DYNAMIC,
            dynamic_offset as u64,
            3 * DYNAMIC_ENTRY_SIZE as u64,
        ));
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[16..18].copy_from_slice(&kind.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(headers.len() as u16).to_le_bytes());
        for (kind, offset, size) in headers {
            let mut header = [0; PROGRAM_HEADER_SIZE];
            header[..4].copy_from_slice(&kind.to_le_bytes());
            header[8..16].copy_from_slice(&offset.to_le_bytes());
            header[32..40].copy_from_slice(&size.to_le_bytes());
            bytes.extend_from_slice(&header);
        }
        assert_eq!(bytes.len(), dynamic_offset);
        for (tag, value) in [
            (if needed { DT_NEEDED } else { 30 }, 1_u64),
            (DT_NULL, 0),
            (DT_NEEDED, 1),
        ] {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn gnu_executables_must_be_dynamic_pie() {
        let target = "x86_64-unknown-linux-gnu";
        assert!(validate(target, &elf(ET_DYN, true, true)).is_ok());
        assert!(
            validate(target, &elf(2, true, true))
                .unwrap_err()
                .contains("ELF type 2")
        );
        assert!(
            validate(target, &elf(ET_DYN, false, true))
                .unwrap_err()
                .contains("no program interpreter")
        );
    }

    #[test]
    fn musl_executables_must_be_static() {
        let target = "x86_64-unknown-linux-musl";
        // The DT_NEEDED entry after DT_NULL does not count.
        assert!(validate(target, &elf(ET_DYN, false, false)).is_ok());
        assert!(
            validate(target, &elf(2, false, false))
                .unwrap_err()
                .contains("ELF type 2")
        );
        assert!(
            validate(target, &elf(ET_DYN, true, false))
                .unwrap_err()
                .contains("program interpreter")
        );
        assert!(
            validate(target, &elf(ET_DYN, false, true))
                .unwrap_err()
                .contains("shared library")
        );
        let target = "aarch64-unknown-linux-musl";
        assert!(validate(target, &elf(2, false, false)).is_ok());
        assert!(validate(target, &elf(ET_DYN, false, false)).is_ok());
        assert!(
            validate(target, &elf(2, true, false))
                .unwrap_err()
                .contains("program interpreter")
        );
        assert!(
            validate(target, &elf(2, false, true))
                .unwrap_err()
                .contains("shared library")
        );
    }

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_CODE_SIGNATURE: u32 = 0x1d;

    /// A minimal Mach-O 64 header for `cpu` and `kind` followed by the given
    /// load commands, each a command and its size. Filler bytes pad every
    /// command to its size.
    fn mach_o(cpu: u32, kind: u32, commands: &[(u32, u32)]) -> Vec<u8> {
        let size: u32 = commands.iter().map(|(_, size)| size).sum();
        let count = u32::try_from(commands.len()).unwrap();
        let mut bytes = Vec::new();
        for value in [MH_MAGIC_64, cpu, 0, kind, count, size, 0, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for (command, size) in commands {
            let start = bytes.len();
            bytes.extend_from_slice(&command.to_le_bytes());
            bytes.extend_from_slice(&size.to_le_bytes());
            bytes.resize(start + usize::try_from(*size).unwrap(), 0xab);
        }
        bytes
    }

    #[test]
    fn macos_executables_must_have_one_uuid() {
        let target = "aarch64-apple-darwin";
        let linked = [(LC_SEGMENT_64, 72), (LC_UUID, 24), (LC_CODE_SIGNATURE, 16)];
        assert!(validate(target, &mach_o(CPU_TYPE_ARM64, MH_EXECUTE, &linked)).is_ok());
        let intel = mach_o(CPU_TYPE_X86_64, MH_EXECUTE, &linked);
        assert!(validate("x86_64-apple-darwin", &intel).is_ok());
        // The shape of a binary linked with -no_uuid, which dyld refuses.
        let no_uuid = mach_o(
            CPU_TYPE_ARM64,
            MH_EXECUTE,
            &[(LC_SEGMENT_64, 72), (LC_CODE_SIGNATURE, 16)],
        );
        assert!(
            validate(target, &no_uuid)
                .unwrap_err()
                .contains("no LC_UUID load command")
        );
        assert!(
            validate(target, &intel)
                .unwrap_err()
                .contains("another CPU")
        );
        let library = mach_o(CPU_TYPE_ARM64, MH_DYLIB, &linked);
        assert!(
            validate(target, &library)
                .unwrap_err()
                .contains("file type 6, not 2")
        );
        assert!(validate_mach_o(target, MH_DYLIB, &library).is_ok());
        let twice = mach_o(CPU_TYPE_ARM64, MH_EXECUTE, &[(LC_UUID, 24), (LC_UUID, 24)]);
        assert!(
            validate(target, &twice)
                .unwrap_err()
                .contains("2 LC_UUID load commands")
        );
        let short = mach_o(CPU_TYPE_ARM64, MH_EXECUTE, &[(LC_UUID, 16)]);
        assert!(
            validate(target, &short)
                .unwrap_err()
                .contains("LC_UUID load command of size 16")
        );
    }

    #[test]
    fn malformed_mach_o_files() {
        let target = "aarch64-apple-darwin";
        assert!(
            validate(target, b"\x7fELF and more")
                .unwrap_err()
                .contains("not a thin 64-bit")
        );
        // A universal binary starts with the big-endian fat magic.
        assert!(
            validate(target, &0xcafe_babe_u32.to_be_bytes())
                .unwrap_err()
                .contains("not a thin 64-bit")
        );
        let good = mach_o(CPU_TYPE_ARM64, MH_EXECUTE, &[(LC_UUID, 24)]);
        assert!(
            validate(target, &good[..20])
                .unwrap_err()
                .contains("truncated")
        );
        assert!(
            validate(target, &good[..40])
                .unwrap_err()
                .contains("out of bounds")
        );
        // The header counts a second command that sizeofcmds has no room for.
        let mut extra = good.clone();
        extra[16] = 2;
        assert!(validate(target, &extra).unwrap_err().contains("truncated"));
        for size in [0_u32, 4, 20, 32] {
            let mut bad = good.clone();
            bad[36..40].copy_from_slice(&size.to_le_bytes());
            assert!(
                validate(target, &bad).unwrap_err().contains("invalid size"),
                "size {size}"
            );
        }
        assert!(
            validate_mach_o("x86_64-unknown-linux-gnu", MH_EXECUTE, &good)
                .unwrap_err()
                .contains("not a macOS release target")
        );
    }

    #[test]
    fn other_targets_and_bad_files() {
        assert!(validate("x86_64-pc-windows-msvc", b"not an ELF file").is_ok());
        let target = "x86_64-unknown-linux-musl";
        assert!(
            validate(target, b"not an ELF file")
                .unwrap_err()
                .contains("not an ELF file")
        );
        let mut truncated = elf(ET_DYN, false, false);
        truncated.truncate(100);
        assert!(
            validate(target, &truncated)
                .unwrap_err()
                .contains("truncated")
        );
        let mut big_endian = elf(ET_DYN, false, false);
        big_endian[5] = 2;
        assert!(
            validate(target, &big_endian)
                .unwrap_err()
                .contains("little-endian")
        );
    }
}
