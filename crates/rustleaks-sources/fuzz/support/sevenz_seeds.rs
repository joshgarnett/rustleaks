//! Synthetic 7z fixtures with explicit member bytes and uncompressed headers.
//!
//! Container construction follows the 7z Header/PackInfo/UnpackInfo/FilesInfo
//! layout. Compression uses the maintained miniz and LZ4 encoders; expected
//! decoded bytes are supplied independently by each caller. No fixture bytes
//! are copied from an upstream archive.

use std::io::Write;

#[derive(Clone, Copy, Debug)]
pub enum Method {
    Copy,
    Deflate,
    Lz4,
}

impl Method {
    fn id(self) -> &'static [u8] {
        match self {
            Self::Copy => &[0],
            Self::Deflate => &[4, 1, 8],
            Self::Lz4 => &[4, 0xf7, 0x11, 4],
        }
    }

    pub fn encode(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Copy => bytes.to_vec(),
            Self::Deflate => miniz_oxide::deflate::compress_to_vec(bytes, 6),
            Self::Lz4 => {
                let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
                encoder.write_all(bytes).expect("encode synthetic LZ4");
                encoder.finish().expect("finish synthetic LZ4")
            }
        }
    }
}

pub struct Member<'a> {
    pub name: &'a str,
    pub method: Method,
    pub packed: Vec<u8>,
    pub size: usize,
    pub crc: u32,
}

impl<'a> Member<'a> {
    pub fn new(name: &'a str, bytes: &[u8], method: Method) -> Self {
        Self {
            name,
            method,
            packed: method.encode(bytes),
            size: bytes.len(),
            crc: crc32(bytes),
        }
    }
}

/// Each member has a separate folder, one coder, and a declared output CRC.
pub fn archive(members: &[Member<'_>]) -> Vec<u8> {
    assert!(!members.is_empty());
    let mut next = vec![1, 4, 6, 0]; // Header, MainStreamsInfo, PackInfo, PackPos.
    number(&mut next, members.len());
    next.push(9); // Pack sizes.
    for member in members {
        number(&mut next, member.packed.len());
    }
    next.extend_from_slice(&[0, 7, 11]); // End PackInfo, UnpackInfo, Folder.
    number(&mut next, members.len());
    next.push(0); // Inline folders.
    for member in members {
        next.push(1); // One coder, one input, one output.
        next.push(u8::try_from(member.method.id().len()).expect("small method ID"));
        next.extend_from_slice(member.method.id());
    }
    next.push(12); // CodersUnpackSize.
    for member in members {
        number(&mut next, member.size);
    }
    next.extend_from_slice(&[10, 1]); // CRC, all defined.
    for member in members {
        next.extend_from_slice(&member.crc.to_le_bytes());
    }
    next.extend_from_slice(&[0, 8, 0, 0, 5]); // End unpack/substreams/main, FilesInfo.
    number(&mut next, members.len());
    let mut names = vec![0]; // Inline UTF-16LE names.
    for member in members {
        for unit in member.name.encode_utf16().chain(std::iter::once(0)) {
            names.extend_from_slice(&unit.to_le_bytes());
        }
    }
    next.push(17);
    number(&mut next, names.len());
    next.extend_from_slice(&names);
    next.extend_from_slice(&[0, 0]); // End FilesInfo, end Header.

    let mut start = Vec::new();
    let packed_size: usize = members.iter().map(|member| member.packed.len()).sum();
    start.extend_from_slice(
        &u64::try_from(packed_size)
            .expect("bounded data")
            .to_le_bytes(),
    );
    start.extend_from_slice(
        &u64::try_from(next.len())
            .expect("bounded header")
            .to_le_bytes(),
    );
    start.extend_from_slice(&crc32(&next).to_le_bytes());
    let mut bytes = b"7z\xbc\xaf'\x1c\x00\x04".to_vec();
    bytes.extend_from_slice(&crc32(&start).to_le_bytes());
    bytes.extend_from_slice(&start);
    for member in members {
        bytes.extend_from_slice(&member.packed);
    }
    bytes.extend_from_slice(&next);
    bytes
}

fn number(output: &mut Vec<u8>, value: usize) {
    if value < 128 {
        output.push(u8::try_from(value).expect("small number"));
    } else {
        output.push(0xff);
        output.extend_from_slice(&u64::try_from(value).expect("bounded number").to_le_bytes());
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// A synthetic folder containing one or more file streams and a linear coder graph.
///
/// Coder order is decode order. Public fields permit deliberate malformed fixtures
/// while keeping header checksums and byte layout internally consistent.
pub struct Folder<'a> {
    pub members: Vec<Member<'a>>,
    pub methods: Vec<Method>,
    pub packed: Vec<u8>,
    pub unpack_sizes: Vec<usize>,
    pub bind_pairs: Vec<(usize, usize)>,
}

impl<'a> Folder<'a> {
    pub fn new(files: &[(&'a str, &[u8])], methods: &[Method]) -> Self {
        assert!(!files.is_empty() && !methods.is_empty());
        let members = files
            .iter()
            .map(|(name, bytes)| Member::new(name, bytes, Method::Copy))
            .collect();
        let mut packed: Vec<u8> = files
            .iter()
            .flat_map(|(_, bytes)| *bytes)
            .copied()
            .collect();
        let mut unpack_sizes = vec![0; methods.len()];
        for (index, method) in methods.iter().enumerate().rev() {
            unpack_sizes[index] = packed.len();
            packed = method.encode(&packed);
        }
        Self {
            members,
            methods: methods.to_vec(),
            packed,
            unpack_sizes,
            bind_pairs: (1..methods.len()).map(|index| (index, index - 1)).collect(),
        }
    }

    /// Declares more output than the encoded stream contains, without corrupting
    /// the container or the independently computed member CRCs.
    pub fn overstate_last_member(&mut self, extra: usize) {
        self.members.last_mut().expect("member").size += extra;
        *self.unpack_sizes.last_mut().expect("coder") += extra;
    }
}

/// Builds folders with explicit substream sizes and per-member CRCs.
fn folder_streams(folders: &[Folder<'_>]) -> Vec<u8> {
    assert!(!folders.is_empty());
    let mut next = vec![6, 0];
    number(&mut next, folders.len());
    next.push(9);
    for folder in folders {
        number(&mut next, folder.packed.len());
    }
    next.extend_from_slice(&[0, 7, 11]);
    number(&mut next, folders.len());
    next.push(0);
    for folder in folders {
        number(&mut next, folder.methods.len());
        for method in &folder.methods {
            next.push(u8::try_from(method.id().len()).expect("small method ID"));
            next.extend_from_slice(method.id());
        }
        for &(input, output) in &folder.bind_pairs {
            number(&mut next, input);
            number(&mut next, output);
        }
    }
    next.push(12);
    for folder in folders {
        for &size in &folder.unpack_sizes {
            number(&mut next, size);
        }
    }
    // No folder CRC: every member has its independent digest below.
    next.extend_from_slice(&[0, 8, 13]);
    for folder in folders {
        number(&mut next, folder.members.len());
    }
    next.push(9);
    for folder in folders {
        for member in &folder.members[..folder.members.len() - 1] {
            number(&mut next, member.size);
        }
    }
    next.extend_from_slice(&[10, 1]);
    for folder in folders {
        for member in &folder.members {
            next.extend_from_slice(&member.crc.to_le_bytes());
        }
    }
    next.extend_from_slice(&[0, 0]);
    next
}

/// Builds folders with explicit substream sizes and per-member CRCs.
pub fn folder_archive(folders: &[Folder<'_>]) -> Vec<u8> {
    let mut next = vec![1, 4];
    next.extend(folder_streams(folders));
    next.push(5);
    number(
        &mut next,
        folders.iter().map(|folder| folder.members.len()).sum(),
    );
    let mut names = vec![0];
    for folder in folders {
        for member in &folder.members {
            for unit in member.name.encode_utf16().chain(std::iter::once(0)) {
                names.extend_from_slice(&unit.to_le_bytes());
            }
        }
    }
    next.push(17);
    number(&mut next, names.len());
    next.extend_from_slice(&names);
    next.extend_from_slice(&[0, 0]);
    folder_envelope(folders, &next)
}

/// Encodes a header stream with the same graph builder as ordinary members.
pub fn encoded_header_archive(folder: &Folder<'_>) -> Vec<u8> {
    let folders = std::slice::from_ref(folder);
    let mut next = vec![23];
    next.extend(folder_streams(folders));
    folder_envelope(folders, &next)
}

fn folder_envelope(folders: &[Folder<'_>], next: &[u8]) -> Vec<u8> {
    let packed: Vec<u8> = folders
        .iter()
        .flat_map(|folder| &folder.packed)
        .copied()
        .collect();
    let mut start = Vec::new();
    start.extend_from_slice(
        &u64::try_from(packed.len())
            .expect("bounded data")
            .to_le_bytes(),
    );
    start.extend_from_slice(
        &u64::try_from(next.len())
            .expect("bounded header")
            .to_le_bytes(),
    );
    start.extend_from_slice(&crc32(next).to_le_bytes());
    let mut bytes = b"7z\xbc\xaf'\x1c\x00\x04".to_vec();
    bytes.extend_from_slice(&crc32(&start).to_le_bytes());
    bytes.extend_from_slice(&start);
    bytes.extend_from_slice(&packed);
    bytes.extend_from_slice(next);
    bytes
}
