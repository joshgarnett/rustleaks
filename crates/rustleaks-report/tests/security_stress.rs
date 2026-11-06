//! Optional larger templates and exact resource boundaries.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[allow(dead_code)]
#[path = "../../rustleaks-core/tests/support/campaign_profile.rs"]
mod campaign_profile;

use campaign_profile::{Profile, deep_seed};
use rustleaks_core::model::{Finding, Location};
use rustleaks_report::{TemplateError, TemplateLimits, TemplateReporter};
use serde_json::json;

fn finding(description: &[u8]) -> Finding {
    Finding::builder()
        .rule_id("structured")
        .description(description)
        .location(Location::new(1, 1, 1, 1).unwrap())
        .build()
        .unwrap()
}

#[test]
fn deep_template_frame_retains_source_past_the_smoke_boundary() {
    let seed = deep_seed("template").unwrap();
    let (_, template, findings) = campaign_profile::template_parts(&seed, Profile::Deep);
    assert_eq!(template.len(), 16 * 1024);
    assert_eq!(findings, b"synthetic-finding");
    let (_, smoke, _) = campaign_profile::template_parts(&seed, Profile::Smoke);
    assert_eq!(smoke.len(), 4 * 1024);
    let limits = Profile::Deep.template();
    assert_eq!(
        (
            limits.source_bytes,
            limits.actions,
            limits.output_bytes,
            limits.findings
        ),
        (32768, 512, 131_072, 16)
    );
}

#[test]
#[ignore = "optional larger-input driver, invoked by the deep-security operator"]
fn security_stress_driver() {
    source_boundary();
    output_boundary();
    action_boundary();
}

fn source_boundary() {
    let caps = Profile::Deep.template();
    let source = vec![b'.'; caps.source_bytes];
    let limits = TemplateLimits::new(caps.source_bytes, caps.actions, caps.output_bytes);
    let reporter = TemplateReporter::from_bytes(&source, limits).unwrap();
    let mut output = Vec::new();
    reporter.render(&mut output, &[]).unwrap();
    assert_eq!(output.len(), source.len());
    assert!(output.iter().all(|byte| *byte == b'.'));
    let below = TemplateLimits::new(caps.source_bytes - 1, caps.actions, caps.output_bytes);
    assert!(
        matches!(TemplateReporter::from_bytes(&source, below), Err(TemplateError::SourceLimit { limit }) if limit == caps.source_bytes - 1)
    );
    println!(
        "{}",
        json!({"kind":"security-stress","case":"template-source","status":"pass","input_bytes":source.len(),"smoke_source_bytes":Profile::Smoke.template().source_bytes,"output_bytes":output.len(),"boundary":"exact-complete-one-less-source-limit"})
    );
}

fn output_boundary() {
    let caps = Profile::Deep.template();
    let bytes = vec![b'.'; caps.output_bytes / caps.findings];
    let findings = (0..caps.findings)
        .map(|_| finding(&bytes))
        .collect::<Vec<_>>();
    let source = b"{{ range . }}{{ .Description }}{{ end }}";
    for subtract in [0, 1] {
        let limit = caps.output_bytes - subtract;
        let reporter = TemplateReporter::from_bytes(
            source,
            TemplateLimits::new(caps.source_bytes, caps.actions, limit),
        )
        .unwrap();
        let mut output = Vec::new();
        let result = reporter.render(&mut output, &findings);
        if subtract == 0 {
            result.unwrap();
            assert_eq!(output.len(), caps.output_bytes);
        } else {
            assert!(
                matches!(result, Err(TemplateError::OutputLimit { limit: actual }) if actual == limit)
            );
            assert!(output.len() <= limit);
        }
        println!(
            "{}",
            json!({"kind":"security-stress","case":if subtract == 0 {"template-output-exact"} else {"template-output-over"},"status":"pass","finding_bytes":caps.output_bytes,"findings":findings.len(),"output_bytes":output.len(),"limit":limit,"smoke_output_bytes":Profile::Smoke.template().output_bytes})
        );
    }
}

fn action_boundary() {
    let caps = Profile::Deep.template();
    // A literal action is evaluated once without range/field traversal costs.
    let source = b"{{ \"x\" }}".repeat(caps.actions);
    assert!(source.len() <= caps.source_bytes);
    for subtract in [0, 1] {
        let limit = caps.actions - subtract;
        let reporter = TemplateReporter::from_bytes(
            &source,
            TemplateLimits::new(caps.source_bytes, limit, caps.output_bytes),
        )
        .unwrap();
        let mut output = Vec::new();
        let result = reporter.render(&mut output, &[]);
        if subtract == 0 {
            result.unwrap();
            assert_eq!(output.len(), caps.actions);
        } else {
            assert!(
                matches!(result, Err(TemplateError::ActionLimit { limit: actual }) if actual == limit)
            );
            assert!(output.len() <= limit);
        }
        println!(
            "{}",
            json!({"kind":"security-stress","case":if subtract == 0 {"template-actions-exact"} else {"template-actions-over"},"status":"pass","input_bytes":source.len(),"actions":caps.actions,"limit":limit,"smoke_actions":Profile::Smoke.template().actions,"output_bytes":output.len()})
        );
    }
}
