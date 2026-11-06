#![forbid(unsafe_code)]
#![no_main]

#[allow(dead_code)]
#[path = "../../../rustleaks-core/tests/support/campaign_profile.rs"]
mod campaign_profile;

use campaign_profile::Profile;

use std::hint::black_box;
use std::io::{self, Write};

use libfuzzer_sys::fuzz_target;
use rustleaks_core::model::{Finding, Location};
use rustleaks_report::{TemplateError, TemplateLimits, TemplateReporter};

struct RejectAfter {
    remaining: usize,
}

impl Write for RejectAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("scheduled writer failure"));
        }
        let count = bytes.len().min(self.remaining);
        self.remaining -= count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.remaining == 0 {
            Err(io::Error::other("scheduled flush failure"))
        } else {
            Ok(())
        }
    }
}

fn finding(index: usize, bytes: &[u8]) -> Finding {
    let line = index.saturating_add(1);
    Finding::builder()
        .rule_id(b"fuzz-template".as_slice())
        .description(bytes)
        .location(Location::new(line, line, 1, bytes.len().saturating_add(1)).expect("ordered"))
        .line(bytes)
        .match_text(bytes)
        .secret(bytes)
        .file(b"fuzz/input".as_slice())
        .entropy(bytes.first().map_or(0.0, |byte| f32::from(*byte) / 32.0))
        .tags([b"fuzz".as_slice(), bytes])
        .build()
        .expect("all required finding fields are present")
}

fuzz_target!(|data: &[u8]| {
    let profile = Profile::current();
    let caps = profile.template();
    let (control, template, finding_bytes) = campaign_profile::template_parts(data, profile);
    let chunk_size = finding_bytes.len().div_ceil(caps.findings).max(1);
    let mut findings = finding_bytes
        .chunks(chunk_size)
        .take(caps.findings)
        .enumerate()
        .map(|(index, bytes)| finding(index, bytes))
        .collect::<Vec<_>>();
    if findings.is_empty() {
        findings.push(finding(0, b"SEED"));
    }

    let limits = TemplateLimits::new(caps.source_bytes, caps.actions, caps.output_bytes);
    if let Ok(reporter) = TemplateReporter::from_bytes(template, limits) {
        let mut output = Vec::new();
        let rendered = reporter.render(&mut output, &findings);
        assert!(output.len() <= caps.output_bytes);
        let _ = black_box(rendered);

        let mut failing = RejectAfter {
            remaining: usize::from(control & 0x3f),
        };
        let _ = black_box(reporter.render(&mut failing, &findings));
    }

    // Writer-error propagation is exercised on every input, including inputs
    // whose arbitrary template is invalid or produces no output.
    let fixed = TemplateReporter::from_bytes(b"prefix={{ .RuleID }}", limits)
        .expect("the fixed safe template parses");
    let mut reject_immediately = RejectAfter { remaining: 0 };
    assert!(matches!(
        fixed.render(&mut reject_immediately, &findings),
        Err(TemplateError::Io(_))
    ));
});
