//! Commit fields that the fragments of one Git commit share.

use std::sync::Arc;

use rustleaks_core::model::{ByteText, CommitMetadata, FragmentBuilder};

/// The commit SHA and metadata of one Git commit.
///
/// Each field is kept once. Every fragment of the commit, from each file,
/// hunk and archive member, refers to the same bytes instead of a copy. The
/// SHA is both the fragment commit and the metadata SHA.
#[derive(Eq, PartialEq)]
pub(crate) struct FragmentCommit {
    sha: Arc<Vec<u8>>,
    author_name: Arc<Vec<u8>>,
    author_email: Arc<Vec<u8>>,
    date: Arc<Vec<u8>>,
    message: Arc<Vec<u8>>,
}

impl FragmentCommit {
    /// Keeps the fields without copying them.
    pub(crate) fn new(
        sha: Vec<u8>,
        author_name: Vec<u8>,
        author_email: Vec<u8>,
        date: Vec<u8>,
        message: Vec<u8>,
    ) -> Self {
        Self {
            sha: Arc::new(sha),
            author_name: Arc::new(author_name),
            author_email: Arc::new(author_email),
            date: Arc::new(date),
            message: Arc::new(message),
        }
    }

    /// Returns the commit SHA.
    #[cfg(any(test, feature = "archives"))]
    pub(crate) fn sha(&self) -> &[u8] {
        &self.sha
    }

    /// Returns the byte length of the metadata fields together.
    pub(crate) fn metadata_len(&self) -> usize {
        [
            &self.sha,
            &self.author_name,
            &self.author_email,
            &self.date,
            &self.message,
        ]
        .iter()
        .fold(0_usize, |total, field| total.saturating_add(field.len()))
    }

    /// Returns the commit metadata, sharing its bytes.
    pub(crate) fn metadata(&self) -> CommitMetadata {
        CommitMetadata::builder()
            .sha(shared(&self.sha))
            .author_name(shared(&self.author_name))
            .author_email(shared(&self.author_email))
            .date(shared(&self.date))
            .message(shared(&self.message))
            .build()
    }

    /// Sets the commit SHA and metadata of a fragment.
    pub(crate) fn apply(&self, builder: FragmentBuilder) -> FragmentBuilder {
        builder
            .commit(shared(&self.sha))
            .commit_metadata(self.metadata())
    }
}

fn shared(bytes: &Arc<Vec<u8>>) -> ByteText {
    ByteText::from_shared(Arc::clone(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustleaks_core::model::Fragment;

    fn commit(sha: &[u8]) -> FragmentCommit {
        FragmentCommit::new(
            sha.to_vec(),
            b"Synthetic Author".to_vec(),
            b"author@example.invalid".to_vec(),
            b"2021-11-02T23:37:53Z".to_vec(),
            b"subject\n\nbody".to_vec(),
        )
    }

    fn metadata(sha: &[u8]) -> CommitMetadata {
        CommitMetadata::builder()
            .sha(sha)
            .author_name("Synthetic Author")
            .author_email("author@example.invalid")
            .date("2021-11-02T23:37:53Z")
            .message("subject\n\nbody")
            .build()
    }

    #[test]
    fn fragments_of_one_commit_share_its_fields_and_keep_their_values() {
        let commit = commit(b"abc123");
        assert_eq!(commit.metadata(), metadata(b"abc123"));
        assert_eq!(commit.metadata_len(), 6 + 16 + 22 + 20 + 13);
        let first = commit.apply(Fragment::builder("one")).build();
        let second = commit.apply(Fragment::builder("two")).build();
        for fragment in [&first, &second] {
            assert_eq!(fragment.commit().as_bytes(), b"abc123");
            assert_eq!(fragment.commit_metadata(), Some(&metadata(b"abc123")));
        }
        let (Some(one), Some(two)) = (first.commit_metadata(), second.commit_metadata()) else {
            panic!("both fragments have metadata");
        };
        for (left, right) in [
            (first.commit(), second.commit()),
            (first.commit(), one.sha()),
            (one.sha(), two.sha()),
            (one.author_name(), two.author_name()),
            (one.author_email(), two.author_email()),
            (one.date(), two.date()),
            (one.message(), two.message()),
        ] {
            assert_eq!(left.as_bytes().as_ptr(), right.as_bytes().as_ptr());
        }
        // A public clone of a fragment still owns its own bytes.
        let cloned = first.clone();
        assert_eq!(cloned, first);
        assert_ne!(
            cloned.commit().as_bytes().as_ptr(),
            first.commit().as_bytes().as_ptr()
        );
        // Dropping the source fields leaves every fragment's bytes in place.
        drop(commit);
        assert_eq!(second.commit_metadata(), Some(&metadata(b"abc123")));
    }
}
