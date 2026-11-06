#![forbid(unsafe_code)]
#![no_main]

#[allow(dead_code)]
#[path = "../../tests/support/campaign_profile.rs"]
mod campaign_profile;

use campaign_profile::Profile;

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;
use rustleaks_core::model::{Finding, Location};
use rustleaks_core::session::{
    Baseline, IgnoreSet, ScanSession, SessionPolicy, SuppressionReason, global_fingerprint,
};

fn finding(bytes: &[u8]) -> Finding {
    let control = bytes.first().copied().unwrap_or_default();
    let line = usize::from(control);
    let body = &bytes[bytes.len().min(1)..];
    Finding::builder()
        .rule_id(b"fuzz-rule".as_slice())
        .description(body)
        .location(Location::new(line, line, 1, body.len().saturating_add(1)).expect("ordered"))
        .line(body)
        .match_text(body)
        .secret(body)
        .file(b"fuzz/input".as_slice())
        .commit(if control & 1 == 0 {
            b"".as_slice()
        } else {
            b"deadbeef".as_slice()
        })
        .entropy(f32::from(control) / 16.0)
        .tags([b"fuzz".as_slice(), body])
        .build()
        .expect("all required finding fields are present")
}

fuzz_target!(|data: &[u8]| {
    let maximum = Profile::current()
        .input_limit("session")
        .expect("known target");
    let data = &data[..data.len().min(maximum)];
    let (baseline_bytes, ignore_bytes, finding_bytes) =
        campaign_profile::session_parts(data, Profile::current());
    let candidate = finding(finding_bytes);

    let arbitrary_baseline = Baseline::from_go_json(baseline_bytes);
    if let Ok(baseline) = &arbitrary_baseline {
        black_box(baseline.is_new(&candidate, usize::from(data.first().copied().unwrap_or(0))));
    }
    let arbitrary_ignores = IgnoreSet::parse_go_compatible(ignore_bytes);
    black_box(arbitrary_ignores.issues.len());
    black_box(arbitrary_ignores.ignores.iter().count());

    let arbitrary_policy = SessionPolicy::builder()
        .ignores(arbitrary_ignores.ignores)
        .build();
    let first = arbitrary_policy.classify(candidate.clone());
    let second = arbitrary_policy.classify(candidate.clone());
    assert_eq!(first.outcome(), second.outcome());

    let baseline_policy = SessionPolicy::builder()
        .baseline(Baseline::from_findings(std::slice::from_ref(&candidate)))
        .build();
    assert_eq!(
        baseline_policy
            .classify(candidate.clone())
            .outcome()
            .suppression_reason(),
        Some(SuppressionReason::Baseline)
    );

    let fingerprint = global_fingerprint(&candidate);
    let exact_ignores = IgnoreSet::parse_go_compatible(fingerprint.as_bytes());
    let policy = SessionPolicy::builder()
        .ignores(exact_ignores.ignores)
        .build();
    let mut session = ScanSession::new(policy);
    let outcome = session.add_finding(candidate);
    assert_eq!(
        outcome.suppression_reason(),
        Some(SuppressionReason::GlobalIgnore)
    );
    assert!(session.findings().is_empty());
});
