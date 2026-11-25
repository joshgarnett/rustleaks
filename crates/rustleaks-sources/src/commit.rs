//! Commit fields that the fragments of one Git commit share.

use std::sync::Arc;

use rustleaks_core::model::{ByteText, CommitMetadata, FragmentBuilder};

/// The commit SHA and metadata of one Git commit.
///
/// Each field is kept once. Every fragment of the commit, from each file,
/// hunk and archive member, refers to the same bytes instead of a copy.
#[derive(Default, Eq, PartialEq)]
pub(crate) struct FragmentCommit {
    sha: Arc<Vec<u8>>,
    metadata: Option<SharedMetadata>,
}

#[derive(Eq, PartialEq)]
struct SharedMetadata {
    sha: Arc<Vec<u8>>,
    author_name: Arc<Vec<u8>>,
    author_email: Arc<Vec<u8>>,
    date: Arc<Vec<u8>>,
    message: Arc<Vec<u8>>,
}

impl FragmentCommit {
    /// Keeps the fields without copying them. A metadata SHA equal to `sha`
    /// shares its bytes.
    pub(crate) fn new(sha: Vec<u8>, metadata: Option<CommitMetadata>) -> Self {
        let sha = Arc::new(sha);
        let metadata = metadata.map(|metadata| SharedMetadata::new(metadata, &sha));
        Self { sha, metadata }
    }

    /// Returns the fragment commit SHA.
    #[cfg(any(test, feature = "archives"))]
    pub(crate) fn sha(&self) -> &[u8] {
        &self.sha
    }

    /// Returns the byte length of the metadata fields together.
    pub(crate) fn metadata_len(&self) -> usize {
        self.metadata.as_ref().map_or(0, |metadata| {
            [
                &metadata.sha,
                &metadata.author_name,
                &metadata.author_email,
                &metadata.date,
                &metadata.message,
            ]
            .iter()
            .fold(0_usize, |total, field| total.saturating_add(field.len()))
        })
    }

    /// Returns the commit metadata, sharing its bytes.
    pub(crate) fn metadata(&self) -> Option<CommitMetadata> {
        self.metadata.as_ref().map(SharedMetadata::metadata)
    }

    /// Sets the commit SHA and metadata of a fragment.
    pub(crate) fn apply(&self, builder: FragmentBuilder) -> FragmentBuilder {
        let builder = builder.commit(ByteText::from_shared(Arc::clone(&self.sha)));
        match self.metadata() {
            Some(metadata) => builder.commit_metadata(metadata),
            None => builder,
        }
    }
}

impl SharedMetadata {
    fn new(metadata: CommitMetadata, commit_sha: &Arc<Vec<u8>>) -> Self {
        let share = |value: &ByteText| Arc::new(value.as_bytes().to_vec());
        let sha = if metadata.sha().as_bytes() == commit_sha.as_slice() {
            Arc::clone(commit_sha)
        } else {
            share(metadata.sha())
        };
        Self {
            sha,
            author_name: share(metadata.author_name()),
            author_email: share(metadata.author_email()),
            date: share(metadata.date()),
            message: share(metadata.message()),
        }
    }

    fn metadata(&self) -> CommitMetadata {
        let shared = |value: &Arc<Vec<u8>>| ByteText::from_shared(Arc::clone(value));
        CommitMetadata::builder()
            .sha(shared(&self.sha))
            .author_name(shared(&self.author_name))
            .author_email(shared(&self.author_email))
            .date(shared(&self.date))
            .message(shared(&self.message))
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustleaks_core::model::Fragment;

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
        let commit = FragmentCommit::new(b"abc123".to_vec(), Some(metadata(b"abc123")));
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

    #[test]
    fn a_different_metadata_sha_and_missing_metadata_are_kept() {
        let commit = FragmentCommit::new(b"abc".to_vec(), Some(metadata(b"def")));
        let fragment = commit.apply(Fragment::builder("x")).build();
        assert_eq!(fragment.commit().as_bytes(), b"abc");
        assert_eq!(fragment.commit_metadata(), Some(&metadata(b"def")));

        let commit = FragmentCommit::new(Vec::new(), None);
        let fragment = commit.apply(Fragment::builder("x")).build();
        assert_eq!(fragment, Fragment::builder("x").commit("").build());
        assert_eq!(fragment.commit_metadata(), None);
    }
}
