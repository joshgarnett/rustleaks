#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use super::{Limits, Request, TARGETS, arguments, corpus, private, process};
use crate::tooling::sha256_bytes;
use private::Bundle;
use process::Outcome;

const SENTINEL: &str = "SYNTHETIC_PRIVATE_FUZZ_SENTINEL";

fn shell(root: &Path, script: &str) -> Command {
    process::command(root, "/bin/sh", &["-c".into(), script.into()])
}

fn cleanup(bundle: &Bundle) {
    // Tests own these synthetic-only trees. Production has no Drop cleanup.
    fs::remove_dir_all(&bundle.path).unwrap();
}

#[test]
fn source_campaign_initialization_retains_legacy_and_adds_framed_seeds_in_each_profile() {
    use super::profiles::{Deadline, Profile};

    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bundle = Bundle::new(None).unwrap();
    let root = bundle.path.join("workspace");
    private::directory(&root).unwrap();
    let mut seeds_directory = root.clone();
    for component in ["crates", "rustleaks-sources", "fuzz", "seeds"] {
        seeds_directory.push(component);
        private::directory(&seeds_directory).unwrap();
    }
    for (name, legacy_file) in [
        ("reader_schedule", "data-error.txt"),
        ("git_patch", "basic.patch"),
    ] {
        let target = TARGETS.iter().find(|target| target.name == name).unwrap();
        let directory = seeds_directory.join(name);
        private::directory(&directory).unwrap();
        // Checked-in runfiles can be symlinks. Materialize their known bytes
        // in this owned private fixture; keep untrusted corpus checks strict.
        let bytes = fs::read(
            target
                .directory(&source_root)
                .join("seeds")
                .join(name)
                .join(legacy_file),
        )
        .unwrap();
        private::write(&directory.join(legacy_file), &bytes).unwrap();
    }
    for profile in [Profile::Smoke, Profile::Deep] {
        for (name, legacy_file, count) in [
            ("reader_schedule", "data-error.txt", 8),
            ("git_patch", "basic.patch", 4),
        ] {
            let original = *TARGETS.iter().find(|target| target.name == name).unwrap();
            let target = super::Target {
                max_len: profile.maximum_input(name).unwrap(),
                ..original
            };
            let directory = bundle.path.join(format!("{}-{name}", profile.name()));
            private::directory(&directory).unwrap();
            let corpus =
                super::seed(&root, &directory, target, profile, Deadline::new(None)).unwrap();
            let expected = super::source_frame::seeds(name);
            assert_eq!(expected.len(), count);
            for (seed_name, bytes) in expected {
                let path = corpus.join(seed_name);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            let legacy_bytes = fs::read(
                target
                    .directory(&source_root)
                    .join("seeds")
                    .join(name)
                    .join(legacy_file),
            )
            .unwrap();
            assert_eq!(
                fs::read(corpus.join(sha256_bytes(&legacy_bytes))).unwrap(),
                legacy_bytes
            );
            let inventory = corpus::inventory(&corpus, target.max_len).unwrap();
            let expected_files = count + 1 + usize::from(profile == Profile::Deep);
            assert_eq!(
                inventory["files"].as_object().unwrap().len(),
                expected_files
            );
            if profile == Profile::Deep {
                assert_eq!(
                    fs::read(corpus.join("structured-deep-input")).unwrap(),
                    super::campaign_profile::deep_seed(name).unwrap()
                );
            }
        }
    }
    cleanup(&bundle);
}

#[test]
fn restrictive_permissions_apply_from_creation_and_to_children() {
    let bundle = Bundle::new(None).unwrap();
    private::json(
        &bundle.path.join("bundle.json"),
        &json!({"state": "preparing"}),
    )
    .unwrap();
    private::write(&bundle.path.join("private"), b"synthetic").unwrap();
    let mut child = shell(
        &bundle.path,
        "printf synthetic > child; mkdir child-directory",
    );
    assert_eq!(
        process::run(&mut child, &bundle.path, Duration::from_secs(5), 1024).unwrap(),
        Outcome::Success
    );
    for name in [
        "private",
        "child",
        "stdout.log",
        "stderr.log",
        "bundle.json",
    ] {
        assert_eq!(
            fs::metadata(bundle.path.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    for path in [&bundle.path, &bundle.path.join("child-directory")] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    cleanup(&bundle);
}

#[test]
fn failure_retains_private_evidence_and_success_cleans_only_implicit_output() {
    let failed = Bundle::new(None).unwrap();
    let path = failed.path.clone();
    let public = failed.finish(Err(SENTINEL.into())).unwrap_err();
    assert!(!public.contains(SENTINEL));
    assert!(public.contains("retained"));
    assert_eq!(
        fs::read_to_string(path.join("failure.txt")).unwrap(),
        SENTINEL
    );
    assert_eq!(
        private::read_json(&path.join("bundle.json")).unwrap()["state"],
        "failure"
    );
    fs::remove_dir_all(path).unwrap();

    let success = Bundle::new(None).unwrap();
    let path = success.path.clone();
    success.finish(Ok(())).unwrap();
    assert!(!path.exists());
    let parent = Bundle::new(None).unwrap();
    let success = Bundle::new(Some(&parent.path.join("explicit"))).unwrap();
    let path = success.path.clone();
    success.finish(Ok(())).unwrap();
    assert!(path.is_dir());
    cleanup(&parent);
}

#[test]
fn crash_capture_and_synthetic_reproduction_preserve_bytes_without_disclosure() {
    let bundle = Bundle::new(None).unwrap();
    let input = bundle.path.join("input");
    private::write(&input, SENTINEL.as_bytes()).unwrap();
    let script = "cat input; cat input >&2; cp input artifact; exit 17";
    let mut child = shell(&bundle.path, script);
    assert_eq!(
        process::run(&mut child, &bundle.path, Duration::from_secs(5), 4096).unwrap(),
        Outcome::ExitFailure
    );
    assert_eq!(
        fs::read(bundle.path.join("artifact")).unwrap(),
        SENTINEL.as_bytes()
    );
    assert_eq!(
        fs::read(bundle.path.join("stdout.log")).unwrap(),
        SENTINEL.as_bytes()
    );
    let reproduction = bundle.path.join("reproduction");
    private::directory(&reproduction).unwrap();
    private::write(
        &reproduction.join("input"),
        &fs::read(bundle.path.join("artifact")).unwrap(),
    )
    .unwrap();
    let mut child = shell(&reproduction, script);
    assert_eq!(
        process::run(&mut child, &reproduction, Duration::from_secs(5), 4096).unwrap(),
        Outcome::ExitFailure
    );
    assert_eq!(
        sha256_bytes(&fs::read(reproduction.join("artifact")).unwrap()),
        sha256_bytes(SENTINEL.as_bytes())
    );
    let path = bundle.path.clone();
    let public = bundle.finish(Err("exit-failure".into())).unwrap_err();
    assert!(!public.contains(SENTINEL));
    assert!(!public.contains(script));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn strict_combined_output_cap_catches_fast_exit_and_continuous_writes() {
    for script in [
        "printf '%01024d' 0; printf '%01024d' 0 >&2",
        "while :; do printf '%01024d' 0; done",
    ] {
        let bundle = Bundle::new(None).unwrap();
        let mut child = shell(&bundle.path, script);
        assert_eq!(
            process::run(&mut child, &bundle.path, Duration::from_secs(5), 128).unwrap(),
            Outcome::OutputLimit
        );
        let length = fs::metadata(bundle.path.join("stdout.log")).unwrap().len()
            + fs::metadata(bundle.path.join("stderr.log")).unwrap().len();
        assert_eq!(length, 128);
        cleanup(&bundle);
    }
}

fn assert_tree_stopped(bundle: &Bundle) {
    let before = fs::read(bundle.path.join("heartbeat")).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        fs::read(bundle.path.join("heartbeat")).unwrap(),
        before,
        "descendant kept writing after cleanup"
    );
    let pid = fs::read_to_string(bundle.path.join("parent.pid"))
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    let pid = rustix::process::Pid::from_raw(pid).unwrap();
    assert_eq!(
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
        rustix::io::Errno::CHILD,
        "direct child was not reaped"
    );
}

const TREE: &str = "echo $$ > parent.pid; (while :; do printf x >> heartbeat; sleep 0.01; done) & while [ ! -s heartbeat ]; do sleep 0.01; done; ";

fn wait_for_fixture_bytes(path: &Path, minimum: u64, deadline: Instant) -> Result<u64, String> {
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "fixture readiness deadline expired: {}",
                path.display()
            ));
        }
        match fs::metadata(path) {
            Ok(metadata) if metadata.len() >= minimum => return Ok(metadata.len()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn establish_tree_readiness(bundle: &Bundle, startup_delay: Duration) -> Result<u64, String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    wait_for_fixture_bytes(&bundle.path.join("startup.waiting"), 1, deadline)?;
    // The gate makes the delayed fixture deterministic: it cannot produce a
    // heartbeat before this monitor has imposed the complete startup delay.
    thread::sleep(startup_delay);
    private::write(&bundle.path.join("start-tree"), b"start")?;
    let heartbeat_bytes = wait_for_fixture_bytes(&bundle.path.join("heartbeat"), 2, deadline)?;
    // Two writes prove descendant activity before either timeout or normal
    // parent exit is allowed to exercise process-group cleanup.
    private::write(&bundle.path.join("release-parent"), b"ready")?;
    Ok(heartbeat_bytes)
}

#[test]
fn timeout_and_early_parent_exit_terminate_descendants_and_reap_parent() {
    for startup_delay in [Duration::ZERO, Duration::from_millis(300)] {
        for (ending, expected, timeout) in [
            ("wait", Outcome::Timeout, Duration::from_millis(200)),
            ("exit 0", Outcome::Success, Duration::from_secs(5)),
        ] {
            let bundle = Bundle::new(None).unwrap();
            let mut child = shell(
                &bundle.path,
                &format!(
                    "echo $$ > parent.pid; printf waiting > startup.waiting; \
                 while [ ! -f start-tree ]; do sleep 0.01; done; \
                 {TREE}while [ ! -f release-parent ]; do sleep 0.01; done; {ending}"
                ),
            );
            let mut readiness = None;
            // The timeout case keeps its 200 ms deadline. Its first monitor
            // waits for bounded fixture readiness, so a slow startup can use
            // that interval without making the descendant assertions vacuous.
            // Normal exit instead has a completion watchdog that includes the
            // separate three-second readiness bound.
            let outcome = process::run_monitored(&mut child, &bundle.path, timeout, 1024, || {
                readiness
                    .get_or_insert_with(|| establish_tree_readiness(&bundle, startup_delay))
                    .as_ref()
                    .map(|_| ())
                    .map_err(Clone::clone)
            })
            .unwrap();
            assert!(
                matches!(readiness, Some(Ok(bytes)) if bytes >= 2),
                "{readiness:?}"
            );
            assert_eq!(outcome, expected, "startup delay: {startup_delay:?}");
            assert_tree_stopped(&bundle);
            cleanup(&bundle);
        }
    }
}

#[test]
fn output_failure_and_corpus_limit_terminate_the_tree() {
    let bundle = Bundle::new(None).unwrap();
    private::write(&bundle.path.join("readonly"), b"").unwrap();
    let mut child = shell(&bundle.path, &format!("{TREE}while :; do printf x; done"));
    let stdout = File::open(bundle.path.join("readonly")).unwrap();
    let stderr = private::file(&bundle.path.join("stderr.log")).unwrap();
    assert_eq!(
        process::run_with_files(
            &mut child,
            stdout,
            stderr,
            Duration::from_secs(5),
            1024,
            || Ok(())
        )
        .unwrap(),
        Outcome::OutputFailure
    );
    assert_tree_stopped(&bundle);
    cleanup(&bundle);

    let bundle = Bundle::new(None).unwrap();
    let mut child = shell(&bundle.path, &format!("{TREE}wait"));
    let marker = bundle.path.join("heartbeat");
    assert_eq!(
        process::run_monitored(
            &mut child,
            &bundle.path,
            Duration::from_secs(5),
            1024,
            || {
                if marker.exists() {
                    Err("synthetic corpus limit".into())
                } else {
                    Ok(())
                }
            }
        )
        .unwrap(),
        Outcome::CorpusLimit
    );
    assert_tree_stopped(&bundle);
    cleanup(&bundle);
}

#[test]
fn command_spawn_and_preparation_failures_retain_bundle_metadata() {
    let bundle = Bundle::new(None).unwrap();
    let mut child = Command::new(bundle.path.join("missing-program"));
    assert_eq!(
        process::run(&mut child, &bundle.path, Duration::from_secs(1), 1024).unwrap(),
        Outcome::SpawnFailure
    );
    let path = bundle.path.clone();
    bundle.finish(Err("spawn-failure".into())).unwrap_err();
    assert!(path.join("bundle.json").exists());
    assert!(path.join("failure.txt").exists());
    fs::remove_dir_all(path).unwrap();

    let bundle = Bundle::new(None).unwrap();
    let path = bundle.path.clone();
    let error = private::directory(&bundle.path).unwrap_err();
    bundle.finish(Err(error)).unwrap_err();
    assert_eq!(
        private::read_json(&path.join("bundle.json")).unwrap()["state"],
        "failure"
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn corpus_rejects_links_traversal_subdirectories_and_oversized_inputs() {
    let bundle = Bundle::new(None).unwrap();
    let corpus = bundle.path.join("corpus");
    private::directory(&corpus).unwrap();
    private::write(&bundle.path.join("outside"), b"synthetic").unwrap();
    symlink(bundle.path.join("outside"), corpus.join("link")).unwrap();
    assert!(corpus::inventory(&corpus, 1024).is_err());
    fs::remove_file(corpus.join("link")).unwrap();
    fs::hard_link(bundle.path.join("outside"), corpus.join("hard-link")).unwrap();
    assert!(corpus::inventory(&corpus, 1024).is_err());
    fs::remove_file(corpus.join("hard-link")).unwrap();
    private::directory(&corpus.join("nested")).unwrap();
    assert!(corpus::inventory(&corpus, 1024).is_err());
    fs::remove_dir(corpus.join("nested")).unwrap();
    private::write(&corpus.join("large"), &[0; 1025]).unwrap();
    assert!(corpus::inventory(&corpus, 1024).is_err());
    assert!(private::checked_path(&corpus.join("../outside")).is_err());
    symlink(&corpus, bundle.path.join("alias")).unwrap();
    assert!(private::checked_path(&bundle.path.join("alias/large")).is_err());
    cleanup(&bundle);
}

#[test]
fn reviewed_corpus_roundtrip_rejects_stale_provenance_and_content() {
    // Promotion is intentionally unavailable in hosted jobs. Test its pure
    // receipt mechanics separately through promote_reviewed below.
    let bundle = Bundle::new(None).unwrap();
    let corpus = bundle.path.join("minimized");
    private::directory(&corpus).unwrap();
    private::write(&corpus.join(sha256_bytes(b"synthetic")), b"synthetic").unwrap();
    let inventory = corpus::inventory(&corpus, 1024).unwrap();
    let identity = json!({"rules": "rules-v1", "toolchain": "compiler-v1", "seeds": "seeds-v1", "dictionary": "dict-v1"});
    let record = json!({"operation": "minimize", "outcome": "success", "target": "config", "identity": identity, "final_corpus": inventory});
    let reviewed = bundle.path.join("reviewed");
    private::directory(&reviewed).unwrap();
    let hash = inventory["sha256"].as_str().unwrap();
    corpus::promote_reviewed(&corpus, &reviewed, &record, hash, 1024).unwrap();
    let imported = bundle.path.join("imported");
    private::directory(&imported).unwrap();
    corpus::import(&reviewed, &imported, &identity, "config", 1024).unwrap();
    assert_eq!(corpus::inventory(&imported, 1024).unwrap(), inventory);
    for field in ["rules", "toolchain", "seeds", "dictionary"] {
        let mut stale = identity.clone();
        stale[field] = json!("changed");
        assert!(corpus::import(&reviewed, &imported, &stale, "config", 1024).is_err());
    }
    private::write(&reviewed.join("corpus/injected"), b"PR mutation").unwrap();
    assert!(corpus::import(&reviewed, &imported, &identity, "config", 1024).is_err());
    assert!(corpus::promote_reviewed(&corpus, &reviewed, &record, &"0".repeat(64), 1024).is_err());
    let mut failed = record.clone();
    failed["outcome"] = json!("exit-failure");
    assert!(corpus::promote_reviewed(&corpus, &reviewed, &failed, hash, 1024).is_err());
    cleanup(&bundle);
}

#[test]
fn replay_reconstructs_bounded_options_and_separates_crash_and_corpus_minimization() {
    let record = json!({"limits": {"runs": 16, "seconds": 20, "seed": 17, "timeout_seconds": 5, "rss_limit_mb": 2048, "log_bytes": process::LOG_LIMIT}, "arguments": ["arbitrary saved command is ignored"]});
    let limits = Limits::from_record(&record).unwrap();
    let build = |operation| {
        arguments(
            Path::new("/source"),
            TARGETS[1],
            Path::new("/private/bundle"),
            &["/private/bundle/corpus".into()],
            limits,
            operation,
            "aarch64-apple-darwin",
        )
    };
    assert_eq!(build("run"), build("replay"));
    let replay = build("replay");
    for option in [
        "-runs=16",
        "-max_total_time=20",
        "-seed=17",
        "-timeout=5",
        "-rss_limit_mb=2048",
        "-max_len=8192",
    ] {
        assert!(replay.iter().any(|value| value == option));
    }
    assert!(!replay.iter().any(|value| value.contains("arbitrary")));
    assert!(build("minimize").contains(&"-merge=1".into()));
    assert!(!build("minimize").contains(&"-minimize_crash=1".into()));
    assert!(build("tmin").contains(&"-minimize_crash=1".into()));
    let mut invalid = record;
    invalid["limits"]["seconds"] = json!(601);
    assert!(Limits::from_record(&invalid).is_err());
    assert!(Request::parse(&["replay".into(), "bundle".into(), "config".into()]).is_err());
    assert!(
        Request::parse(&[
            "run".into(),
            "--output".into(),
            "/private/tmp/name with spaces".into()
        ])
        .is_ok()
    );
}

#[test]
fn crash_minimization_leaves_input_length_initialization_to_libfuzzer() {
    let limits = Limits {
        runs: 16,
        seconds: 20,
        seed: 17,
    };
    for target in TARGETS {
        for operation in ["run", "replay", "reproduce", "minimize", "tmin"] {
            let options = arguments(
                Path::new("/source"),
                *target,
                Path::new("/private/bundle"),
                &["/private/bundle/reproducer".into()],
                limits,
                operation,
                "aarch64-apple-darwin",
            );
            let maximum_lengths = options
                .iter()
                .filter(|option| option.starts_with("-max_len="))
                .collect::<Vec<_>>();
            if operation == "tmin" {
                assert!(maximum_lengths.is_empty());
                assert!(options.contains(&"-minimize_crash=1".into()));
            } else {
                assert_eq!(maximum_lengths, [&format!("-max_len={}", target.max_len)]);
            }
            for bound in ["-max_total_time=20", "-timeout=5", "-rss_limit_mb=2048"] {
                assert!(options.iter().any(|option| option == bound));
            }
        }
    }
}

#[test]
fn explicit_profiles_preserve_smoke_and_bind_deep_inputs_to_replay() {
    use super::profiles::{Deadline, Profile};
    for target in TARGETS {
        assert_eq!(
            Profile::Smoke.maximum_input(target.name).unwrap(),
            target.max_len
        );
        assert_eq!(
            Profile::Extended.maximum_input(target.name).unwrap(),
            target.max_len
        );
        assert_eq!(Profile::Deep.maximum_input(target.name).unwrap(), 65_536);
        let seed = super::campaign_profile::deep_seed(target.name).unwrap();
        assert!(seed.len() as u64 > target.max_len);
        assert!(seed.len() <= 65_536);
    }
    let request = Request::parse(&[
        "run".into(),
        "--profile".into(),
        "deep".into(),
        "--targets".into(),
        "config".into(),
        "--seconds".into(),
        "60".into(),
    ])
    .unwrap();
    assert_eq!(request.limits().unwrap().seconds, 60);
    assert_eq!(request.limits().unwrap().runs, 1_000_000);
    assert_eq!(
        Profile::from_record(&serde_json::Value::Null).unwrap(),
        Profile::Smoke
    );
    let mut stale = Profile::Deep.record();
    stale["version"] = json!(2);
    assert!(Profile::from_record(&stale).is_err());
    assert!(
        Deadline::new(None)
            .intersect(Deadline::new(Some(0)))
            .expired()
    );
    assert!(
        Deadline::new(Some(0))
            .remaining(Duration::from_mins(1))
            .is_err()
    );
    assert!(
        Request::parse(&[
            "replay".into(),
            "bundle".into(),
            "config".into(),
            "--output".into(),
            "new".into(),
            "--profile".into(),
            "deep".into()
        ])
        .is_err()
    );
}

#[test]
fn feedback_and_failure_classification_do_not_publish_diagnostic_payloads() {
    let feedback = super::feedback(
        "#2 INITED cov: 10 ft: 12 corp: 1/4b\nSYNTHETIC_PRIVATE_VALUE\n#20 DONE cov: 14 ft: 18 corp: 3/18b\n",
    );
    assert_eq!(feedback["covered_edges"], 14);
    assert_eq!(feedback["features"], 18);
    assert_eq!(feedback["executions"], 20);
    assert!(!feedback.to_string().contains("SYNTHETIC_PRIVATE_VALUE"));
    assert_eq!(
        super::classify(Outcome::ExitFailure, &json!({"files":{"oom-synthetic":{}}})),
        "out-of-memory"
    );
    assert_eq!(
        super::classify(
            Outcome::ExitFailure,
            &json!({"files":{"timeout-synthetic":{}}})
        ),
        "input-timeout"
    );
    assert_eq!(
        super::classify(Outcome::Timeout, &json!({"files":{}})),
        "runner-timeout"
    );
}

#[test]
fn wrapper_request_is_persisted_before_source_preparation() {
    use super::profiles::Deadline;
    let bundle = Bundle::new(None).unwrap();
    let request = Request::parse(&[
        "run".into(),
        "--profile".into(),
        "deep".into(),
        "--targets".into(),
        "config".into(),
        "--seconds".into(),
        "60".into(),
        "--deadline-seconds".into(),
        "10".into(),
    ])
    .unwrap();
    let deadline = Deadline::new(Some(10));
    let invocation = request.normalized(Deadline::new(None), deadline);
    assert!(
        super::execute(
            &bundle.path.join("missing-source"),
            &bundle,
            &request,
            deadline,
            &invocation
        )
        .is_err()
    );
    let record = private::read_json(&bundle.path.join("bundle.json")).unwrap();
    assert_eq!(record["state"], "preparing");
    assert_eq!(record["request"]["operation"], "run");
    assert_eq!(record["request"]["targets"], json!(["config"]));
    assert_eq!(record["request"]["profile"]["name"], "deep");
    assert_eq!(record["request"]["limit_overrides"]["seconds"], 60);
    assert_eq!(
        record["request"]["wrapper_deadline"]["requested_seconds"],
        10
    );
    assert_eq!(record["request"]["wrapper_deadline"]["local_seconds"], 10);
    assert_eq!(
        record["request"]["wrapper_deadline"]["local_source"],
        "explicit-option"
    );
    assert_eq!(
        record["request"]["wrapper_deadline"]["inherited_at_start"]["bounded"],
        false
    );
    assert_eq!(
        record["request"]["wrapper_deadline"]["effective_at_start"]["bounded"],
        true
    );
    cleanup(&bundle);
}

#[test]
fn supervisor_metadata_distinguishes_requested_child_budget_and_remaining_deadline() {
    use super::profiles::Deadline;
    let maximum = Duration::from_mins(3);
    let (unbounded, record) = Deadline::new(None).supervisor(maximum);
    assert_eq!(unbounded, maximum);
    assert_eq!(record["requested_maximum_ms"], 180_000);
    assert_eq!(record["effective_timeout_ns"], json!(maximum.as_nanos()));
    assert_eq!(record["deadline_constrained"], false);
    assert!(record["operation_remaining_ns_at_selection"].is_null());
    let (constrained, record) = Deadline::new(Some(10)).supervisor(maximum);
    assert!(constrained <= Duration::from_secs(10));
    assert_eq!(record["requested_maximum_ms"], 180_000);
    assert_eq!(
        record["effective_timeout_ns"],
        json!(constrained.as_nanos())
    );
    assert_eq!(record["deadline_constrained"], true);
    let (expired, record) = Deadline::new(Some(0)).supervisor(maximum);
    assert!(expired.is_zero());
    assert_eq!(record["effective_timeout_ns"], 0);
    assert_eq!(record["deadline_constrained"], true);
}

#[test]
fn inherited_deadline_and_fresh_replay_policy_remain_explicit() {
    use super::profiles::Deadline;
    let request = Request::parse(&["run".into(), "--profile".into(), "deep".into()]).unwrap();
    let outer = Deadline::new(Some(10));
    let record = request.normalized(outer, outer.intersect(Deadline::new(Some(7200))));
    assert_eq!(
        record["wrapper_deadline"]["local_source"],
        "profile-default"
    );
    assert_eq!(record["wrapper_deadline"]["local_seconds"], 7200);
    assert!(record["wrapper_deadline"]["requested_seconds"].is_null());
    assert_eq!(
        record["wrapper_deadline"]["inherited_at_start"]["bounded"],
        true
    );
    assert!(
        record["wrapper_deadline"]["effective_at_start"]["remaining_ns"]
            .as_u64()
            .unwrap()
            <= 10_000_000_000
    );
    let replay = Request::parse(&[
        "replay".into(),
        "bundle".into(),
        "config".into(),
        "--output".into(),
        "new".into(),
    ])
    .unwrap();
    let record = replay.normalized(Deadline::new(None), Deadline::new(None));
    assert_eq!(record["profile_source"], "saved-target-manifest");
    assert_eq!(record["targets"], json!(["config"]));
    assert!(record["wrapper_deadline"]["local_seconds"].is_null());
    assert_eq!(
        record["wrapper_deadline"]["effective_at_start"]["bounded"],
        false
    );
    assert_eq!(
        record["wrapper_deadline"]["replay_policy"],
        "fresh invocation deadline; saved elapsed wall-clock budget is not reused"
    );
}

#[test]
fn expired_preparation_records_its_supervisor_without_launching_a_child() {
    use super::profiles::Deadline;
    let bundle = Bundle::new(None).unwrap();
    assert!(
        super::captured(
            &bundle.path,
            &bundle.path,
            "expired",
            "/bin/sh",
            &[],
            Duration::from_secs(30),
            Deadline::new(Some(0))
        )
        .is_err()
    );
    let record = private::read_json(&bundle.path.join("expired/command.json")).unwrap();
    assert_eq!(record["outcome"], "not-started-deadline");
    assert_eq!(record["supervisor"]["requested_maximum_ms"], 30_000);
    assert_eq!(record["supervisor"]["effective_timeout_ns"], 0);
    assert!(!bundle.path.join("expired/stdout.log").exists());
    cleanup(&bundle);
}
