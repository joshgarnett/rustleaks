//! Executable check for the dependency boundary selected by `panic=abort`.
#![forbid(unsafe_code)]

#[cfg(panic = "abort")]
fn main() {
    use std::io::Cursor;

    use rustleaks_sources::{
        ArchiveSource, CancellationToken, Source, SourceControl, SourceEvent, SourceIssueKind,
    };

    let bytes = include_bytes!("../../../compat/fixtures/upstream/testdata/archives/files.7z");
    let mut source = ArchiveSource::new(Cursor::new(bytes.as_slice()), "files.7z");
    let mut fragments = 0_usize;
    let mut issues = Vec::new();
    source
        .visit(&CancellationToken::new(), &mut |event| {
            match event {
                SourceEvent::Fragment { issue, .. } => {
                    fragments += 1;
                    if let Some(issue) = issue {
                        issues.push(issue.kind());
                    }
                }
                SourceEvent::Issue(issue) => issues.push(issue.kind()),
                _ => unreachable!("future source event"),
            }
            Ok(SourceControl::Continue)
        })
        .expect("abort-profile 7z rejection is recoverable");
    assert_eq!(fragments, 0, "abort profile entered the 7z decoder");
    assert_eq!(issues, [SourceIssueKind::UnsupportedArchive]);
}

#[cfg(not(panic = "abort"))]
fn main() {}
