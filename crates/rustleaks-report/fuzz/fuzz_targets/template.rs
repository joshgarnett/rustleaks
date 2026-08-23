#![forbid(unsafe_code)]
#![no_main]

use std::hint::black_box;
use std::io::{self, Write};

use rustleaks_core::model::{Finding, Location};
use rustleaks_report::{TemplateError, TemplateLimits, TemplateReporter};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_TEMPLATE_BYTES: usize = 4 * 1024;
const MAX_ACTIONS: usize = 128;
const MAX_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_FINDINGS: usize = 4;

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

fn framed(data: &[u8]) -> (u8, &[u8], &[u8]) {
    let control = data.first().copied().unwrap_or_default();
    let rest = &data[data.len().min(1)..];
    let Some((&low, rest)) = rest.split_first() else {
        return (control, &[], &[]);
    };
    let Some((&high, payload)) = rest.split_first() else {
        return (control, &[], &[]);
    };
    let requested = usize::from(u16::from_le_bytes([low, high]));
    let template_len = requested.min(MAX_TEMPLATE_BYTES).min(payload.len());
    let (template, findings) = payload.split_at(template_len);
    (control, template, findings)
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let (control, template, finding_bytes) = framed(data);
    let chunk_size = finding_bytes.len().div_ceil(MAX_FINDINGS).max(1);
    let mut findings = finding_bytes
        .chunks(chunk_size)
        .take(MAX_FINDINGS)
        .enumerate()
        .map(|(index, bytes)| finding(index, bytes))
        .collect::<Vec<_>>();
    if findings.is_empty() {
        findings.push(finding(0, b"SEED"));
    }

    let limits = TemplateLimits::new(MAX_TEMPLATE_BYTES, MAX_ACTIONS, MAX_OUTPUT_BYTES);
    if let Ok(reporter) = TemplateReporter::from_bytes(template, limits) {
        let mut output = Vec::new();
        let rendered = reporter.render(&mut output, &findings);
        assert!(output.len() <= MAX_OUTPUT_BYTES);
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
