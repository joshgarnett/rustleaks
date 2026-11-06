//! Bounded test-only fuzz profiles and synthetic larger-input seeds.

use std::sync::OnceLock;

pub const DEEP_INPUT_BYTES: usize = 64 * 1024;
pub const PROFILE_ENV: &str = "RUSTLEAKS_FUZZ_PROFILE";
pub const TARGETS: &[&str] = &[
    "go_regex",
    "config",
    "fragment_scan",
    "session",
    "archive",
    "reader_schedule",
    "git_patch",
    "template",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    Smoke,
    Deep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveProfile {
    pub depth: usize,
    pub entries: usize,
    pub member_bytes: usize,
    pub total_bytes: usize,
    pub input_bytes: usize,
    pub chunk_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentProfile {
    pub input_bytes: usize,
    pub decode_depth: usize,
    pub decoded_bytes: usize,
    pub work_units: usize,
    pub finding_records: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemplateProfile {
    pub input_bytes: usize,
    pub source_bytes: usize,
    pub actions: usize,
    pub output_bytes: usize,
    pub findings: usize,
}

impl Profile {
    pub fn from_name(name: Option<&str>) -> Result<Self, &'static str> {
        match name {
            None | Some("smoke" | "extended") => Ok(Self::Smoke),
            Some("deep") => Ok(Self::Deep),
            Some(_) => Err("unsupported fuzz harness profile"),
        }
    }

    pub fn current() -> Self {
        static PROFILE: OnceLock<Profile> = OnceLock::new();
        *PROFILE.get_or_init(|| {
            let value = std::env::var_os(PROFILE_ENV);
            let value = value
                .as_ref()
                .map(|value| value.to_str().expect("fuzz profile must be UTF-8"));
            Self::from_name(value).expect("unsupported fuzz harness profile")
        })
    }

    pub fn input_limit(self, target: &str) -> Option<usize> {
        let smoke = match target {
            "go_regex" | "reader_schedule" => 4 * 1024,
            "config" | "fragment_scan" | "archive" | "template" => 8 * 1024,
            "session" | "git_patch" => 16 * 1024,
            _ => return None,
        };
        Some(if self == Self::Deep {
            DEEP_INPUT_BYTES
        } else {
            smoke
        })
    }

    pub const fn archive(self) -> ArchiveProfile {
        match self {
            Self::Smoke => ArchiveProfile {
                depth: 2,
                entries: 8,
                member_bytes: 128 * 1024,
                total_bytes: 128 * 1024,
                input_bytes: 8 * 1024,
                chunk_bytes: 512,
            },
            Self::Deep => ArchiveProfile {
                depth: 4,
                entries: 256,
                member_bytes: 1024 * 1024,
                total_bytes: 4 * 1024 * 1024,
                input_bytes: DEEP_INPUT_BYTES,
                chunk_bytes: 4 * 1024,
            },
        }
    }

    pub const fn fragment(self) -> FragmentProfile {
        match self {
            Self::Smoke => FragmentProfile {
                input_bytes: 8 * 1024,
                decode_depth: 2,
                decoded_bytes: 32 * 1024,
                work_units: 4 * 1024,
                finding_records: 64,
            },
            Self::Deep => FragmentProfile {
                input_bytes: DEEP_INPUT_BYTES,
                decode_depth: 4,
                decoded_bytes: 2 * 1024 * 1024,
                work_units: 64 * 1024,
                finding_records: 512,
            },
        }
    }

    pub const fn template(self) -> TemplateProfile {
        match self {
            Self::Smoke => TemplateProfile {
                input_bytes: 8 * 1024,
                source_bytes: 4 * 1024,
                actions: 128,
                output_bytes: 8 * 1024,
                findings: 4,
            },
            Self::Deep => TemplateProfile {
                input_bytes: DEEP_INPUT_BYTES,
                source_bytes: 32 * 1024,
                actions: 512,
                output_bytes: 128 * 1024,
                findings: 16,
            },
        }
    }
}

/// Shared framing lets deterministic tests prove the reader consumes a longer schedule.
pub fn reader_parts(data: &[u8], profile: Profile) -> (u8, &[u8], &[u8]) {
    let cap = profile
        .input_limit("reader_schedule")
        .expect("known target");
    let data = &data[..data.len().min(cap)];
    let control = data.first().copied().unwrap_or_default();
    let rest = &data[data.len().min(1)..];
    let (requested, rest) = if profile == Profile::Deep {
        match rest {
            [low, high, payload @ ..] => (usize::from(u16::from_le_bytes([*low, *high])), payload),
            _ => (0, &[][..]),
        }
    } else {
        (rest.first().map_or(0, |value| usize::from(*value)), rest)
    };
    let (schedule, payload) = rest.split_at(requested % (rest.len() + 1));
    (control, schedule, payload)
}

pub fn regex_parts(data: &[u8], profile: Profile) -> Option<(&[u8], &[u8])> {
    let cap = profile.input_limit("go_regex").expect("known target");
    let data = &data[..data.len().min(cap)];
    let [low, high, payload @ ..] = data else {
        return None;
    };
    let requested = usize::from(u16::from_le_bytes([*low, *high]));
    Some(payload.split_at(requested % (payload.len() + 1)))
}

pub fn session_parts(data: &[u8], profile: Profile) -> (&[u8], &[u8], &[u8]) {
    let cap = profile.input_limit("session").expect("known target");
    let data = &data[..data.len().min(cap)];
    let [low, high, payload @ ..] = data else {
        return (&[], &[], &[]);
    };
    let baseline_len = usize::from(u16::from_le_bytes([*low, *high])) % (payload.len() + 1);
    let (baseline, rest) = payload.split_at(baseline_len);
    let ignore_len = rest
        .first()
        .map_or(0, |value| usize::from(*value) % (rest.len() + 1));
    let (ignore, finding) = rest.split_at(ignore_len);
    (baseline, ignore, finding)
}

pub fn template_parts(data: &[u8], profile: Profile) -> (u8, &[u8], &[u8]) {
    let limits = profile.template();
    let data = &data[..data.len().min(limits.input_bytes)];
    let control = data.first().copied().unwrap_or_default();
    let rest = &data[data.len().min(1)..];
    let [low, high, payload @ ..] = rest else {
        return (control, &[], &[]);
    };
    let requested = usize::from(u16::from_le_bytes([*low, *high]));
    let (template, findings) =
        payload.split_at(requested.min(limits.source_bytes).min(payload.len()));
    (control, template, findings)
}

/// One deterministic, nonfunctional seed per target that exceeds its smoke input cap.
pub fn deep_seed(target: &str) -> Option<Vec<u8>> {
    let data = match target {
        "go_regex" => {
            let mut bytes = vec![4, 0];
            bytes.extend_from_slice(b"tail");
            bytes.resize(DEEP_INPUT_BYTES - 4, b'.');
            bytes.extend_from_slice(b"tail");
            bytes
        }
        "config" => {
            let rule = b"\n[[rules]]\nid = \"deep\"\nregex = 'tail'\n";
            let mut bytes = vec![b'#'];
            bytes.resize(DEEP_INPUT_BYTES - rule.len(), b'.');
            bytes.extend_from_slice(rule);
            bytes
        }
        "fragment_scan" => {
            let suffix = b"\nsecret=DEEPVALUE\n";
            let mut bytes = vec![0];
            bytes.resize(DEEP_INPUT_BYTES - suffix.len(), b'.');
            bytes.extend_from_slice(suffix);
            bytes
        }
        "session" => {
            let mut bytes = vec![2, 0, b'[', b']', 0, 0];
            bytes.resize(DEEP_INPUT_BYTES, b'.');
            bytes
        }
        "archive" => {
            let mut bytes = b"RLA\x01\x00\x00".to_vec();
            bytes.extend_from_slice(&synthetic_tar(&[("large.txt", &vec![b'.'; 32 * 1024])]));
            bytes
        }
        "reader_schedule" => {
            let mut bytes = vec![0, 0, 32];
            bytes.resize(3 + 8192, 15);
            bytes.extend(std::iter::repeat_n(b'.', 8192));
            bytes
        }
        "git_patch" => {
            let mut bytes = vec![0];
            bytes.extend_from_slice(b"diff --git a/large.txt b/large.txt\nnew file mode 100644\n--- /dev/null\n+++ b/large.txt\n@@ -0,0 +1,512 @@\n");
            for _ in 0..512 {
                bytes.push(b'+');
                bytes.extend(std::iter::repeat_n(b'.', 64));
                bytes.push(b'\n');
            }
            bytes
        }
        "template" => {
            let mut bytes = vec![0, 0, 64];
            bytes.resize(3 + 16 * 1024, b'.');
            bytes.extend_from_slice(b"synthetic-finding");
            bytes
        }
        _ => return None,
    };
    assert!(data.len() > Profile::Smoke.input_limit(target).expect("known target"));
    assert!(data.len() <= DEEP_INPUT_BYTES);
    Some(data)
}

/// Small USTAR writer for synthetic test inputs; no filesystem or external compressor.
pub fn synthetic_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    for &(name, body) in entries {
        assert!(name.len() <= 100);
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: usize = header.iter().map(|&byte| usize::from(byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        output.extend_from_slice(&header);
        output.extend_from_slice(body);
        output.resize(output.len().div_ceil(512) * 512, 0);
    }
    output.resize(output.len() + 1024, 0);
    output
}
