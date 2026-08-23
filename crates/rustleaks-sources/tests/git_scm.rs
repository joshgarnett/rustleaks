//! Git remote discovery and source-control link parity tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use rustleaks_core::model::{Finding, Location};
use rustleaks_sources::{
    Cancellation, CancellationToken, RemoteMetadata, ScmErrorKind, ScmPlatform, scm_link,
};

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn finding(commit: &str, file: &str, start_line: usize, end_line: usize) -> Finding {
    Finding::builder()
        .rule_id("test-rule")
        .location(Location::new(start_line, end_line, 0, 0).expect("valid test location"))
        .commit(commit)
        .file(file)
        .build()
        .expect("complete test finding")
}

fn link(
    platform: ScmPlatform,
    remote: &str,
    commit: &str,
    file: &str,
    start_line: usize,
    end_line: usize,
) -> String {
    RemoteMetadata::new(platform, remote)
        .link_for(&finding(commit, file, start_line, end_line))
        .expect("link allocation")
        .expect("supported platform link")
        .as_str()
        .expect("ASCII test link")
        .to_owned()
}

#[test]
fn matrix_l_remote_normalization_platform_names_match_the_contract() {
    let cases = [
        ("", ScmPlatform::Unknown, "unknown"),
        ("UnKnOwN", ScmPlatform::Unknown, "unknown"),
        ("NONE", ScmPlatform::NoPlatform, "none"),
        ("GitHub", ScmPlatform::GitHub, "github"),
        ("GITLAB", ScmPlatform::GitLab, "gitlab"),
        ("AzureDevOps", ScmPlatform::AzureDevOps, "azuredevops"),
        ("GITEA", ScmPlatform::Gitea, "gitea"),
        ("BitBucket", ScmPlatform::Bitbucket, "bitbucket"),
    ];
    for (input, expected, display) in cases {
        let parsed = ScmPlatform::from_str(input).expect("valid platform");
        assert_eq!(parsed, expected, "input={input}");
        assert_eq!(parsed.to_string(), display, "input={input}");
    }
    assert_eq!(
        ScmPlatform::from_str("sourcehut")
            .expect_err("unsupported platform")
            .kind(),
        ScmErrorKind::InvalidPlatform
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table keeps every pinned upstream link vector auditable"
)]
fn matrix_m_link_templates_are_exact() {
    let cases = [
        (
            ScmPlatform::GitHub,
            "https://github.com/gitleaks/test",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "metrics/% of sales/.env",
            25,
            25,
            "https://github.com/gitleaks/test/blob/20553ad96a4a080c94a54d677db97eed8ce2560d/metrics/%25%20of%20sales/.env#L25",
        ),
        (
            ScmPlatform::GitHub,
            "https://github.com/gitleaks/test",
            "7bad9f7654cf9701b62400281748c0e8efd97666",
            "config.json",
            235,
            238,
            "https://github.com/gitleaks/test/blob/7bad9f7654cf9701b62400281748c0e8efd97666/config.json#L235-L238",
        ),
        (
            ScmPlatform::GitHub,
            "https://github.com/gitleaks/test",
            "1fc8961d172f39ffb671766e472aa76f8d713e87",
            "docs/guides/ecosystem/discordjs.MD",
            34,
            34,
            "https://github.com/gitleaks/test/blob/1fc8961d172f39ffb671766e472aa76f8d713e87/docs/guides/ecosystem/discordjs.MD?plain=1#L34",
        ),
        (
            ScmPlatform::GitHub,
            "https://github.com/gitleaks/test",
            "8f56bd2369595bcadbb007e88ba294630fb05c7b",
            "Cloud/IPYNB/Overlapping Recommendation algorithm _OCuLaR_.ipynb",
            293,
            293,
            "https://github.com/gitleaks/test/blob/8f56bd2369595bcadbb007e88ba294630fb05c7b/Cloud/IPYNB/Overlapping%20Recommendation%20algorithm%20_OCuLaR_.ipynb?plain=1#L293",
        ),
        (
            ScmPlatform::GitLab,
            "https://gitlab.com/example-org/example-group/gitleaks",
            "213ffd1c9bfa906eb4c7731771132c58a4ca0139",
            ".gitlab-ci.yml",
            41,
            41,
            "https://gitlab.com/example-org/example-group/gitleaks/blob/213ffd1c9bfa906eb4c7731771132c58a4ca0139/.gitlab-ci.yml#L41",
        ),
        (
            ScmPlatform::GitLab,
            "https://gitlab.com/example-org/example-group/gitleaks",
            "63410f74e23a4e51e1f60b9feb073b5d325af878",
            ".vscode/launchSettings.json",
            6,
            8,
            "https://gitlab.com/example-org/example-group/gitleaks/blob/63410f74e23a4e51e1f60b9feb073b5d325af878/.vscode/launchSettings.json#L6-8",
        ),
        (
            ScmPlatform::AzureDevOps,
            "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "examplefile.json",
            25,
            25,
            "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository/commit/20553ad96a4a080c94a54d677db97eed8ce2560d?path=/examplefile.json&line=25&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files",
        ),
        (
            ScmPlatform::AzureDevOps,
            "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "examplefile.json",
            25,
            30,
            "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository/commit/20553ad96a4a080c94a54d677db97eed8ce2560d?path=/examplefile.json&line=25&lineEnd=30&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files",
        ),
        (
            ScmPlatform::Gitea,
            "https://gitea.com/exampleorganisation/exampleproject",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "examplefile.json",
            25,
            25,
            "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#L25",
        ),
        (
            ScmPlatform::Gitea,
            "https://gitea.com/exampleorganisation/exampleproject",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "examplefile.json",
            25,
            30,
            "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#L25-L30",
        ),
        (
            ScmPlatform::Gitea,
            "https://gitea.com/exampleorganisation/exampleproject",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "Readme.md",
            34,
            34,
            "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/Readme.md?display=source#L34",
        ),
        (
            ScmPlatform::Bitbucket,
            "https://bitbucket.org/exampleorganisation/exampleproject",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "examplefile.json",
            25,
            25,
            "https://bitbucket.org/exampleorganisation/exampleproject/src/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#lines-25",
        ),
        (
            ScmPlatform::Bitbucket,
            "https://bitbucket.org/exampleorganisation/exampleproject",
            "20553ad96a4a080c94a54d677db97eed8ce2560d",
            "examplefile.json",
            25,
            30,
            "https://bitbucket.org/exampleorganisation/exampleproject/src/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#lines-25:30",
        ),
    ];

    for (platform, remote, commit, file, start, end, expected) in cases {
        assert_eq!(
            link(platform, remote, commit, file, start, end),
            expected,
            "platform={platform} file={file}"
        );
    }
}

#[test]
fn archive_members_use_the_escaped_outer_path_without_line_or_display_suffixes() {
    let finding = finding("abc123", "outer % archive.zip!inner/README.md", 12, 14);
    let cases = [
        (
            ScmPlatform::GitHub,
            "https://github.com/o/r",
            "https://github.com/o/r/blob/abc123/outer%20%25%20archive.zip",
        ),
        (
            ScmPlatform::GitLab,
            "https://gitlab.com/o/r",
            "https://gitlab.com/o/r/blob/abc123/outer%20%25%20archive.zip",
        ),
        (
            ScmPlatform::AzureDevOps,
            "https://dev.azure.com/o/p/_git/r",
            "https://dev.azure.com/o/p/_git/r/commit/abc123?path=/outer%20%25%20archive.zip",
        ),
        (
            ScmPlatform::Gitea,
            "https://gitea.com/o/r",
            "https://gitea.com/o/r/src/commit/abc123/outer%20%25%20archive.zip",
        ),
        (
            ScmPlatform::Bitbucket,
            "https://bitbucket.org/o/r",
            "https://bitbucket.org/o/r/src/abc123/outer%20%25%20archive.zip",
        ),
    ];
    for (platform, url, expected) in cases {
        let remote = RemoteMetadata::new(platform, url);
        assert_eq!(
            remote
                .link_for(&finding)
                .expect("link allocation")
                .expect("archive link")
                .as_bytes(),
            expected.as_bytes()
        );
    }
}

#[test]
fn link_paths_only_escape_original_spaces_and_percent_bytes() {
    let file = "dir #/?/snowman-☃\\literal% name.rs";
    assert_eq!(
        link(
            ScmPlatform::GitHub,
            "https://github.com/o/r",
            "abc123",
            file,
            0,
            9,
        ),
        "https://github.com/o/r/blob/abc123/dir%20#/?/snowman-☃\\literal%25%20name.rs-L9"
    );
    assert_eq!(
        link(
            ScmPlatform::AzureDevOps,
            "https://dev.azure.com/o/p/_git/r",
            "abc123",
            file,
            0,
            9,
        ),
        "https://dev.azure.com/o/p/_git/r/commit/abc123?path=/dir%20#/?/snowman-☃\\literal%25%20name.rs&lineEnd=9&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files"
    );
}

#[test]
fn absent_unknown_disabled_and_commitless_metadata_produce_no_link() {
    let populated = finding("abc123", "src/lib.rs", 1, 1);
    let commitless = finding("", "src/lib.rs", 1, 1);
    assert_eq!(scm_link(None, &populated).expect("no allocation"), None);
    assert_eq!(
        RemoteMetadata::new(ScmPlatform::Unknown, "https://example.com/o/r")
            .link_for(&populated)
            .expect("no allocation"),
        None
    );
    assert_eq!(
        RemoteMetadata::new(ScmPlatform::NoPlatform, "")
            .link_for(&populated)
            .expect("no allocation"),
        None
    );
    assert_eq!(
        RemoteMetadata::new(ScmPlatform::GitHub, "https://github.com/o/r")
            .link_for(&commitless)
            .expect("no allocation"),
        None
    );
}

#[test]
fn no_platform_returns_without_spawning_even_when_cancelled() {
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let remote = RemoteMetadata::discover_with_executable(
        ScmPlatform::NoPlatform,
        Path::new("directory-that-does-not-exist"),
        "executable-that-does-not-exist",
        &cancellation,
    )
    .expect("NoPlatform bypasses cancellation, path, and executable checks");
    assert_eq!(remote.platform(), ScmPlatform::NoPlatform);
    assert!(remote.url().is_empty());
}

#[test]
fn cancellation_before_spawn_is_explicit() {
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let error = RemoteMetadata::discover_with_executable(
        ScmPlatform::Unknown,
        Path::new("."),
        "executable-that-does-not-exist",
        &cancellation,
    )
    .expect_err("cancelled discovery");
    assert_eq!(error.kind(), ScmErrorKind::Cancelled);
}

#[test]
fn cancellation_after_spawn_reaps_and_joins_the_git_child() {
    struct CancelAfterPreflight {
        checks: AtomicUsize,
    }

    impl Cancellation for CancelAfterPreflight {
        fn is_cancelled(&self) -> bool {
            self.checks.fetch_add(1, Ordering::Relaxed) != 0
        }
    }

    let cancellation = CancelAfterPreflight {
        checks: AtomicUsize::new(0),
    };
    let error = RemoteMetadata::discover(ScmPlatform::Unknown, Path::new("."), &cancellation)
        .expect_err("second cancellation check occurs after spawn");
    assert_eq!(error.kind(), ScmErrorKind::Cancelled);
}

#[test]
fn dot_source_uses_the_callers_current_repository_without_a_directory_override() {
    let result = RemoteMetadata::discover(
        ScmPlatform::Unknown,
        Path::new("."),
        &CancellationToken::new(),
    );
    if let Err(error) = result {
        assert_ne!(
            error.kind(),
            ScmErrorKind::Spawn,
            "the caller's existing current directory must not be rejected"
        );
    }
}

#[test]
fn discovers_first_remote_and_normalizes_scp_syntax() {
    let repository = TestRepository::new(&[
        ("origin", "git@GitHub.com:2222/example/first.git"),
        ("second", "https://gitlab.com/example/second.git"),
    ]);
    let remote = RemoteMetadata::discover(
        ScmPlatform::Unknown,
        repository.path(),
        &CancellationToken::new(),
    )
    .expect("discover first remote");
    assert_eq!(remote.platform(), ScmPlatform::GitHub);
    assert_eq!(remote.url().as_bytes(), b"https://GitHub.com/example/first");
}

#[test]
fn normalizes_https_and_ssh_credentials_and_preserves_forced_platforms() {
    let cases = [
        (
            ScmPlatform::Unknown,
            "https://user:secret@GitLab.com/example/repo.git",
            ScmPlatform::GitLab,
            "https://GitLab.com/example/repo",
        ),
        (
            ScmPlatform::Unknown,
            "ssh://git@codeberg.org/example/repo.git",
            ScmPlatform::Gitea,
            "ssh://codeberg.org/example/repo",
        ),
        (
            ScmPlatform::Unknown,
            "git@github.com:example/repo.git",
            ScmPlatform::GitHub,
            "https://github.com/example/repo",
        ),
        (
            ScmPlatform::Bitbucket,
            "https://user@unknown.example:8443/example/repo.git",
            ScmPlatform::Bitbucket,
            "https://unknown.example:8443/example/repo",
        ),
        (
            ScmPlatform::Unknown,
            "https://user:secret@GitHub.com:8443/example/repo.git?view=1#readme",
            ScmPlatform::GitHub,
            "https://GitHub.com:8443/example/repo.git?view=1#readme",
        ),
        (
            ScmPlatform::Unknown,
            "https://github.com/example/repo.GIT",
            ScmPlatform::GitHub,
            "https://github.com/example/repo.GIT",
        ),
    ];

    for (requested, input, expected_platform, expected_url) in cases {
        let repository = TestRepository::new(&[("origin", input)]);
        let remote =
            RemoteMetadata::discover(requested, repository.path(), &CancellationToken::new())
                .expect("valid remote");
        assert_eq!(remote.platform(), expected_platform, "input={input}");
        assert_eq!(
            remote.url().as_bytes(),
            expected_url.as_bytes(),
            "input={input}"
        );
    }
}

#[test]
fn maps_all_known_hosts_and_retains_unknown_hosts() {
    let cases = [
        ("github.com", ScmPlatform::GitHub),
        ("gitlab.com", ScmPlatform::GitLab),
        ("dev.azure.com", ScmPlatform::AzureDevOps),
        ("visualstudio.com", ScmPlatform::AzureDevOps),
        ("gitea.com", ScmPlatform::Gitea),
        ("code.forgejo.org", ScmPlatform::Gitea),
        ("codeberg.org", ScmPlatform::Gitea),
        ("bitbucket.org", ScmPlatform::Bitbucket),
        ("example.com", ScmPlatform::Unknown),
    ];
    for (host, expected) in cases {
        let repository =
            TestRepository::new(&[("origin", &format!("https://{host}/example/repo.git"))]);
        let remote = RemoteMetadata::discover(
            ScmPlatform::Unknown,
            repository.path(),
            &CancellationToken::new(),
        )
        .expect("valid host remote");
        assert_eq!(remote.platform(), expected, "host={host}");
    }
}

#[test]
fn absent_and_invalid_remotes_are_safe_recoverable_outcomes() {
    let absent = TestRepository::new(&[]);
    let remote = RemoteMetadata::discover(
        ScmPlatform::GitHub,
        absent.path(),
        &CancellationToken::new(),
    )
    .expect("absent remote is not exceptional");
    assert_eq!(remote.platform(), ScmPlatform::NoPlatform);
    assert!(remote.url().is_empty());

    let invalid = TestRepository::new(&[("origin", "https://github.com/example/%zz.git")]);
    let error = RemoteMetadata::discover(
        ScmPlatform::Unknown,
        invalid.path(),
        &CancellationToken::new(),
    )
    .expect_err("invalid percent escape is reported");
    assert_eq!(error.kind(), ScmErrorKind::InvalidRemote);

    for malformed in [
        "https://github.com:not-a-port/example/repo.git",
        "person@github.com:example/repo.git",
    ] {
        let repository = TestRepository::new(&[("origin", malformed)]);
        let error = RemoteMetadata::discover(
            ScmPlatform::Unknown,
            repository.path(),
            &CancellationToken::new(),
        )
        .expect_err("malformed remote is reported without a panic");
        assert_eq!(error.kind(), ScmErrorKind::InvalidRemote);
    }
}

struct TestRepository {
    path: PathBuf,
}

impl TestRepository {
    fn new(remotes: &[(&str, &str)]) -> Self {
        let path = loop {
            let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let candidate = std::env::temp_dir()
                .join(format!("rustleaks-scm-{}-{sequence}", std::process::id()));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create temporary repository: {error}"),
            }
        };
        let initialized = Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&path)
            .status()
            .expect("spawn git init");
        assert!(initialized.success(), "initialize temporary repository");
        for (name, url) in remotes {
            let configured = Command::new("git")
                .args(["remote", "add", name, url])
                .current_dir(&path)
                .status()
                .expect("spawn git remote add");
            assert!(configured.success(), "configure remote {name}");
        }
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestRepository {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove temporary repository");
    }
}
