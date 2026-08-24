use std::path::{Component, Path, PathBuf};

use rustleaks_core::model::ByteText;

/// Separator between an archive container path and its logical member path.
pub const INNER_PATH_SEPARATOR: &str = "!";

/// Byte-preserving logical path metadata derived from a native path.
///
/// On Unix, native path bytes are retained exactly. On Windows, ill-formed
/// UTF-16 is replaced one code unit at a time as Go does when constructing a
/// UTF-8 string, and the normalized form replaces native backslashes with `/`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalPath {
    normalized: ByteText,
    windows_original: Option<ByteText>,
}

impl LogicalPath {
    /// Converts a physical native path without filesystem canonicalization or
    /// Unicode normalization.
    #[must_use]
    pub fn from_native(path: &Path) -> Self {
        let original = native_path_bytes(path);
        #[cfg(windows)]
        {
            let normalized: Vec<u8> = original
                .iter()
                .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
                .collect();
            Self {
                normalized: ByteText::new(normalized),
                windows_original: Some(ByteText::new(original)),
            }
        }
        #[cfg(not(windows))]
        {
            Self {
                normalized: ByteText::new(original),
                windows_original: None,
            }
        }
    }

    /// Returns the logical path supplied to the engine.
    #[must_use]
    pub const fn normalized(&self) -> &ByteText {
        &self.normalized
    }

    /// Returns the original Windows spelling retained for dual-path matching.
    #[must_use]
    pub fn windows_original(&self) -> Option<&ByteText> {
        self.windows_original.as_ref()
    }

    #[cfg(feature = "archives")]
    pub(crate) fn joined_archive(&self, inner: &[u8], _native_inner: &[u8]) -> Self {
        let mut normalized = self.normalized.as_bytes().to_vec();
        normalized.extend_from_slice(INNER_PATH_SEPARATOR.as_bytes());
        normalized.extend_from_slice(inner);
        #[cfg(windows)]
        let windows_original = {
            // Upstream slash-normalizes every completed outer archive path and
            // retains native separators only for the current inner member.
            let mut original = self.normalized.as_bytes().to_vec();
            original.extend_from_slice(INNER_PATH_SEPARATOR.as_bytes());
            original.extend_from_slice(_native_inner);
            Some(ByteText::new(original))
        };
        #[cfg(not(windows))]
        let windows_original = None;
        Self {
            normalized: ByteText::new(normalized),
            windows_original,
        }
    }
}

#[cfg(unix)]
fn native_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn native_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;

    let mut result = Vec::new();
    for decoded in char::decode_utf16(path.as_os_str().encode_wide()) {
        let character = decoded.unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut encoded = [0_u8; 4];
        result.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
    }
    result
}

#[cfg(not(any(unix, windows)))]
fn native_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

pub(crate) fn clean_native_path(path: &Path) -> PathBuf {
    let mut prefix = None;
    let mut rooted = false;
    let mut parts = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix = Some(value.as_os_str().to_os_string()),
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|part| part != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push(std::ffi::OsString::from(".."));
                }
            }
            Component::Normal(value) => parts.push(value.to_os_string()),
        }
    }

    let mut result = PathBuf::new();
    if let Some(prefix) = prefix {
        result.push(prefix);
    }
    if rooted {
        result.push(std::path::MAIN_SEPARATOR_STR);
    }
    for part in parts {
        result.push(part);
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_clean_preserves_leading_parent() {
        assert_eq!(
            clean_native_path(Path::new("../a/./b/../c")),
            Path::new("../a/c")
        );
    }

    #[cfg(unix)]
    #[test]
    fn logical_path_preserves_invalid_unix_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"bad-\xff-name"));
        let logical = LogicalPath::from_native(path);
        assert_eq!(logical.normalized().as_bytes(), b"bad-\xff-name");
        assert!(logical.windows_original().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn logical_windows_path_retains_original_and_normalizes_slashes() {
        let logical = LogicalPath::from_native(Path::new(r"C:\work\mixed/path"));
        assert_eq!(logical.normalized().as_bytes(), b"C:/work/mixed/path");
        assert_eq!(
            logical
                .windows_original()
                .expect("Windows original")
                .as_bytes(),
            br"C:\work\mixed/path"
        );
    }

    #[cfg(all(windows, feature = "archives"))]
    #[test]
    fn windows_archive_path_normalizes_completed_outer_segments() {
        let outer = LogicalPath::from_native(Path::new(r"C:\work\outer.zip"));
        let inner = outer.joined_archive(b"dir/member.tar", br"dir\member.tar");
        assert_eq!(
            inner.normalized().as_bytes(),
            b"C:/work/outer.zip!dir/member.tar"
        );
        assert_eq!(
            inner
                .windows_original()
                .expect("Windows archive path")
                .as_bytes(),
            br"C:/work/outer.zip!dir\member.tar"
        );

        let nested = inner.joined_archive(b"leaf/value", br"leaf\value");
        assert_eq!(
            nested
                .windows_original()
                .expect("nested Windows archive path")
                .as_bytes(),
            br"C:/work/outer.zip!dir/member.tar!leaf\value"
        );
    }
}
