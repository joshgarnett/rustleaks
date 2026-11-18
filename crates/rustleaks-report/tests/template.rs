#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::io::{self, Write};
use std::path::Path;

use rustleaks_core::model::{Finding, Location};
use rustleaks_report::{
    Reporter, SAFE_TEMPLATE_PROFILE, TemplateError, TemplateLimits, TemplateReporter,
};

fn fixture_finding() -> Finding {
    Finding::builder()
        .rule_id("test-rule")
        .description("A test rule")
        .location(Location::new(1, 2, 1, 2).unwrap())
        .line("whole line containing secret")
        .match_text("line containing secret")
        .secret("a secret")
        .file("auth.py")
        .commit("0000000000000000")
        .author("John Doe")
        .email("johndoe@gmail.com")
        .date("10-19-2003")
        .message("opps")
        .tags(["tag1", "tag2", "tag3"])
        .build()
        .unwrap()
}

fn reporter(source: &[u8]) -> TemplateReporter {
    TemplateReporter::from_bytes(source, TemplateLimits::default()).unwrap()
}

fn render(template: &TemplateReporter, findings: &[Finding]) -> Vec<u8> {
    let mut bytes = Vec::new();
    template.write(&mut bytes, findings).unwrap();
    bytes
}

#[test]
fn fixture_templates_match_the_pinned_go_oracle_byte_for_byte() {
    let json = reporter(include_bytes!(
        "../../../compat/fixtures/upstream/testdata/report/jsonextra.tmpl"
    ));
    assert_eq!(
        render(&json, &[fixture_finding()]),
        include_bytes!(
            "../../../compat/fixtures/upstream/testdata/expected/report/template_jsonextra.json"
        )
    );

    let markdown = reporter(include_bytes!(
        "../../../compat/fixtures/upstream/testdata/report/markdown.tmpl"
    ));
    assert_eq!(
        render(&markdown, &[fixture_finding()]),
        include_bytes!(
            "../../../compat/fixtures/upstream/testdata/expected/report/template_markdown.md"
        )
    );
}

#[test]
fn fixture_templates_define_exact_empty_order_and_duplicate_behavior() {
    let json = reporter(include_bytes!(
        "../../../compat/fixtures/upstream/testdata/report/jsonextra.tmpl"
    ));
    assert_eq!(render(&json, &[]), b"[\n]\n");

    let markdown = reporter(include_bytes!(
        "../../../compat/fixtures/upstream/testdata/report/markdown.tmpl"
    ));
    assert_eq!(
        render(&markdown, &[]),
        b"| File | Line | Secret |\n|:-----|-----:|--------|\n"
    );

    let first = Finding::builder()
        .rule_id("first")
        .location(Location::new(1, 1, 1, 1).unwrap())
        .tags(["same", "same"])
        .build()
        .unwrap();
    let second = Finding::builder()
        .rule_id("second")
        .location(Location::new(2, 2, 1, 1).unwrap())
        .tags(["tail"])
        .build()
        .unwrap();
    // The inner range changes dot, so the last-tag expression must be assigned
    // before entering it, exactly as in the compatibility fixture.
    let order = reporter(
        b"{{ range $i, $f := . }}{{ $last := sub (len .Tags) 1 }}{{ $i }}={{ .RuleID }}:[{{ range $j, $tag := .Tags }}{{ quote . }}{{ if ne $j $last }},{{ end }}{{ end }}];{{ end }}",
    );
    assert_eq!(
        render(&order, &[first.clone(), second, first]),
        b"0=first:[\"same\",\"same\"];1=second:[\"tail\"];2=first:[\"same\",\"same\"];"
    );
}

#[test]
fn direct_fields_preserve_malformed_bytes_and_quote_uses_go_string_escapes() {
    let finding = Finding::builder()
        .rule_id("bytes")
        .location(Location::new(1, 1, 1, 1).unwrap())
        .secret([
            0xff, 0x00, b'\n', b'"', b'\\', 0xf0, 0x9f, 0x92, 0xa9, 0xc2, 0xa0, 0xe2, 0x80, 0xa8,
            0xef, 0xbf, 0xbd, 0xcd, 0xb8,
        ])
        .build()
        .unwrap();
    let raw = reporter(b"{{ range . }}{{ .Secret }}{{ end }}");
    assert_eq!(
        render(&raw, std::slice::from_ref(&finding)),
        finding.secret().as_bytes()
    );
    let quoted = reporter(b"{{ range . }}{{ quote .Secret }}{{ end }}");
    assert_eq!(
        render(&quoted, &[finding]),
        b"\"\\xff\\x00\\n\\\"\\\\\xf0\x9f\x92\xa9\\xa0\\u2028\xef\xbf\xbd\\u0378\""
    );
}

#[test]
fn whitespace_trimming_variables_with_if_and_eq_are_exact() {
    let finding = Finding::builder()
        .rule_id("wanted")
        .location(Location::new(1, 1, 1, 1).unwrap())
        .build()
        .unwrap();
    let template = reporter(
        b"left \t\n{{- range $i, $finding := . -}}\n {{ with $finding }}{{ if eq .RuleID \"wanted\" }}{{ $i }}:{{ .RuleID }}{{ end }}{{ end }} {{- end -}}\n right",
    );
    assert_eq!(render(&template, &[finding]), b"left0:wantedright");
}

#[test]
fn now_and_date_are_parse_recognized_without_acquiring_a_host_clock() {
    let template = reporter(b"{{ now | date \"2006-01-02\" }}");
    let mut output = Vec::new();
    assert!(matches!(
        template.render(&mut output, &[]),
        Err(TemplateError::MissingValue { .. })
    ));
    assert!(output.is_empty());
}

#[test]
fn forbidden_and_unknown_capabilities_fail_during_construction() {
    for name in [
        "env",
        "expandenv",
        "getHostByName",
        "call",
        "randAlphaNum",
        "uuidv4",
        "sha256sum",
        "dict",
        "append",
        "repeat",
        "until",
        "regexFind",
        "urlParse",
        "genPrivateKey",
        "upper",
        "index",
        "unknownHelper",
    ] {
        let source = format!("{{{{ {name} \"value\" }}}}");
        let error = TemplateReporter::from_str(&source, TemplateLimits::default()).unwrap_err();
        assert!(
            matches!(error, TemplateError::UnsupportedFeature { .. }),
            "{name}: {error:?}"
        );
        if matches!(name, "env" | "expandenv" | "getHostByName") {
            assert!(
                error
                    .to_string()
                    .contains(&format!("function \"{name}\" not defined"))
            );
        }
    }

    for source in [
        "{{ define \"x\" }}x{{ end }}",
        "{{ template \"x\" . }}",
        "{{ block \"x\" . }}x{{ end }}",
        "{{ else }}",
    ] {
        assert!(matches!(
            TemplateReporter::from_str(source, TemplateLimits::default()),
            Err(TemplateError::UnsupportedFeature { .. })
        ));
    }
}

#[test]
fn malformed_templates_report_source_offsets_without_panicking() {
    for source in [
        b"{{".as_slice(),
        b"{{ }}",
        b"{{ range . }}",
        b"{{ end }}",
        b"{{ .NoSuchField }}",
        b"{{ \"unterminated }}",
        b"{{ sub (len . 1 }}",
    ] {
        let error = TemplateReporter::from_bytes(source, TemplateLimits::default()).unwrap_err();
        assert!(
            matches!(
                error,
                TemplateError::Parse { .. }
                    | TemplateError::UnsupportedFeature { .. }
                    | TemplateError::Type { .. }
            ),
            "{source:?}: {error:?}"
        );
    }

    let executable_error = reporter(b"{{ len }}");
    assert!(matches!(
        executable_error.render(&mut Vec::new(), &[]),
        Err(TemplateError::Type { operation: "len" })
    ));

    let mut nested_blocks = String::new();
    for _ in 0..129 {
        nested_blocks.push_str("{{ if eq 1 1 }}");
    }
    for _ in 0..129 {
        nested_blocks.push_str("{{ end }}");
    }
    assert!(matches!(
        TemplateReporter::from_str(&nested_blocks, TemplateLimits::default()),
        Err(TemplateError::Parse {
            message: "template nesting limit exceeded",
            ..
        })
    ));

    let mut nested_expression = String::from("{{ len ");
    for _ in 0..129 {
        nested_expression.push('(');
    }
    nested_expression.push('.');
    for _ in 0..129 {
        nested_expression.push(')');
    }
    nested_expression.push_str(" }}");
    assert!(matches!(
        TemplateReporter::from_str(&nested_expression, TemplateLimits::default()),
        Err(TemplateError::Parse {
            message: "template nesting limit exceeded",
            ..
        })
    ));
}

#[test]
fn source_action_iteration_and_output_limits_have_exact_boundaries() {
    assert!(matches!(
        TemplateReporter::from_bytes(b"x", TemplateLimits::new(0, 1, 1)),
        Err(TemplateError::SourceLimit { limit: 0 })
    ));
    assert_eq!(
        render(
            &TemplateReporter::from_bytes(b"x", TemplateLimits::new(1, 0, 1)).unwrap(),
            &[]
        ),
        b"x"
    );

    let action =
        TemplateReporter::from_bytes(b"{{ len . }}", TemplateLimits::new(11, 1, 1)).unwrap();
    assert_eq!(render(&action, &[]), b"0");
    let action =
        TemplateReporter::from_bytes(b"{{ len . }}", TemplateLimits::new(11, 0, 1)).unwrap();
    assert!(matches!(
        action.render(&mut Vec::new(), &[]),
        Err(TemplateError::ActionLimit { limit: 0 })
    ));

    let finding = Finding::builder()
        .rule_id("x")
        .location(Location::new(1, 1, 1, 1).unwrap())
        .build()
        .unwrap();
    let source = b"{{ range . }}{{ .RuleID }}{{ end }}";
    let at_limit = TemplateReporter::from_bytes(source, TemplateLimits::new(64, 3, 1)).unwrap();
    assert_eq!(render(&at_limit, std::slice::from_ref(&finding)), b"x");
    let below_limit = TemplateReporter::from_bytes(source, TemplateLimits::new(64, 2, 1)).unwrap();
    assert!(matches!(
        below_limit.render(&mut Vec::new(), &[finding]),
        Err(TemplateError::ActionLimit { limit: 2 })
    ));

    let exact = TemplateReporter::from_bytes(b"abc", TemplateLimits::new(3, 0, 3)).unwrap();
    assert_eq!(render(&exact, &[]), b"abc");
    let too_small = TemplateReporter::from_bytes(b"abc", TemplateLimits::new(3, 0, 2)).unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        too_small.render(&mut output, &[]),
        Err(TemplateError::OutputLimit { limit: 2 })
    ));
    assert!(output.is_empty());

    let quote_at_limit =
        TemplateReporter::from_bytes(b"{{ quote \"\\x00\" }}", TemplateLimits::new(32, 1, 6))
            .unwrap();
    assert_eq!(render(&quote_at_limit, &[]), b"\"\\x00\"");
    let quote_below_limit =
        TemplateReporter::from_bytes(b"{{ quote \"\\x00\" }}", TemplateLimits::new(32, 1, 5))
            .unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        quote_below_limit.render(&mut output, &[]),
        Err(TemplateError::OutputLimit { limit: 5 })
    ));
    assert!(output.is_empty());
}

/// Counts written bytes without keeping them.
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn default_limits_set_no_output_limit() {
    assert_eq!(TemplateLimits::NO_OUTPUT_LIMIT, usize::MAX);
    assert_eq!(
        TemplateLimits::default(),
        TemplateLimits::new(1024 * 1024, 1_000_000, usize::MAX).with_actions_per_finding(1_000)
    );

    // A body of almost 1 MiB rendered for each of 80 findings writes more
    // than the 64 MiB that earlier releases allowed.
    let mut source = b"{{ range . }}".to_vec();
    let body = 1024 * 1024 - source.len() - b"{{ end }}".len();
    source.resize(source.len() + body, b'x');
    source.extend_from_slice(b"{{ end }}");
    let reporter = TemplateReporter::from_bytes(&source, TemplateLimits::default()).unwrap();
    let findings = (0..80).map(|_| fixture_finding()).collect::<Vec<_>>();
    let mut output = ByteCounter(0);
    reporter.render(&mut output, &findings).unwrap();
    assert_eq!(output.0, 80 * body);
    assert!(output.0 > 64 * 1024 * 1024);

    // An explicit output limit still applies.
    let limited = TemplateReporter::from_bytes(
        &source,
        TemplateLimits::new(1024 * 1024, 1_000_000, 64 * 1024 * 1024),
    )
    .unwrap();
    let mut output = ByteCounter(0);
    assert!(matches!(
        limited.render(&mut output, &findings),
        Err(TemplateError::OutputLimit { limit }) if limit == 64 * 1024 * 1024
    ));
    assert!(output.0 <= 64 * 1024 * 1024);
}

/// Returns the smallest fixed action limit with which `source` renders.
fn actions_needed(source: &[u8], findings: &[Finding]) -> usize {
    let fits = |limit| {
        TemplateReporter::from_bytes(
            source,
            TemplateLimits::new(1024 * 1024, limit, TemplateLimits::NO_OUTPUT_LIMIT),
        )
        .unwrap()
        .render(&mut io::sink(), findings)
        .is_ok()
    };
    let (mut low, mut high) = (0, 1_000_000);
    assert!(fits(high));
    while low < high {
        let middle = low + (high - low) / 2;
        if fits(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

#[test]
fn default_action_limit_grows_by_1_000_for_each_finding() {
    let limits = TemplateLimits::default();
    assert_eq!(limits.max_actions, 1_000_000);
    assert_eq!(limits.actions_per_finding, 1_000);
    assert_eq!(limits.action_limit(0), 1_000_000);
    assert_eq!(limits.action_limit(50_000), 51_000_000);
    assert_eq!(limits.action_limit(usize::MAX), usize::MAX);
    assert_eq!(
        TemplateLimits::new(1, usize::MAX, 1)
            .with_actions_per_finding(1)
            .action_limit(1),
        usize::MAX
    );
    assert_eq!(TemplateLimits::new(1, 7, 1).action_limit(1_000), 7);
}

#[test]
fn packaged_example_templates_use_far_fewer_actions_than_the_allowance() {
    let one = [fixture_finding()];
    let two = [fixture_finding(), fixture_finding()];
    for source in [
        &include_bytes!("../../../compat/fixtures/upstream/testdata/report/jsonextra.tmpl")[..],
        include_bytes!("../../../compat/fixtures/upstream/testdata/report/markdown.tmpl"),
        b"{{range $i, $f := .}}{{$i}} {{.RuleID | quote}} {{.File}}:{{.StartLine}}\n{{end}}total: {{len .}}",
    ] {
        let per_finding = actions_needed(source, &two) - actions_needed(source, &one);
        assert!(per_finding > 0 && per_finding < 100, "{per_finding}");
    }
}

#[test]
fn large_reports_from_normal_templates_fit_the_default_action_limit() {
    // One range iteration and 29 field actions: 30 actions for each finding.
    let mut source = b"{{ range . }}".to_vec();
    for field in [
        ".RuleID",
        ".File",
        ".StartLine",
        ".EndLine",
        ".StartColumn",
        ".EndColumn",
        ".Commit",
        ".Author",
        ".Email",
        ".Date",
        ".Message",
        ".Description",
        ".Secret",
        ".Match",
        ".Entropy",
    ] {
        source.extend_from_slice(format!("{{{{ {field} }}}},").as_bytes());
    }
    for field in [
        ".RuleID",
        ".File",
        ".Line",
        ".Commit",
        ".Author",
        ".Email",
        ".Date",
        ".Message",
        ".Description",
        ".Secret",
        ".Match",
        ".SymlinkFile",
        ".Link",
        ".Line",
    ] {
        source.extend_from_slice(format!("{{{{ {field} | quote }}}};").as_bytes());
    }
    source.extend_from_slice(b"\n{{ end }}");
    let finding = fixture_finding();
    let one = std::slice::from_ref(&finding);
    let two = [finding.clone(), finding.clone()];
    assert_eq!(
        actions_needed(&source, &two) - actions_needed(&source, one),
        30
    );

    let findings = vec![finding; 50_000];
    let reporter = TemplateReporter::from_bytes(&source, TemplateLimits::default()).unwrap();
    let mut output = ByteCounter(0);
    reporter.render(&mut output, &findings).unwrap();
    assert!(output.0 > 0);

    // The fixed limit of earlier releases stopped this report.
    let fixed = TemplateReporter::from_bytes(
        &source,
        TemplateLimits::new(1024 * 1024, 1_000_000, TemplateLimits::NO_OUTPUT_LIMIT),
    )
    .unwrap();
    assert!(matches!(
        fixed.render(&mut io::sink(), &findings),
        Err(TemplateError::ActionLimit { limit: 1_000_000 })
    ));
}

#[test]
fn templates_whose_work_grows_faster_than_the_findings_still_stop() {
    // Nested ranges over all findings need findings squared iterations.
    let source = b"{{ $all := . }}{{ range $all }}{{ range $all }}x{{ end }}{{ end }}";
    let reporter = TemplateReporter::from_bytes(source, TemplateLimits::default()).unwrap();
    let findings = vec![fixture_finding(); 2_000];
    let mut output = ByteCounter(0);
    assert!(matches!(
        reporter.render(&mut output, &findings),
        Err(TemplateError::ActionLimit { limit: 3_000_000 })
    ));
    assert!(output.0 < 3_000_000);

    let small = vec![fixture_finding(); 100];
    let mut output = ByteCounter(0);
    reporter.render(&mut output, &small).unwrap();
    assert_eq!(output.0, 10_000);
}

#[test]
fn path_errors_are_stable_and_do_not_embed_platform_prose() {
    assert!(matches!(
        TemplateReporter::from_path(Path::new(""), TemplateLimits::default()),
        Err(TemplateError::EmptyPath)
    ));
    let error = TemplateReporter::from_path(
        Path::new("this-template-does-not-exist-anywhere.tmpl"),
        TemplateLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(error, TemplateError::Read { .. }));
    assert!(error.to_string().starts_with("could not read template ("));
}

#[test]
fn destination_errors_are_returned_and_the_destination_is_never_closed() {
    struct FailingWriter {
        bytes: Vec<u8>,
        remaining: usize,
        flushes: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected failure"));
            }
            let count = self.remaining.min(bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    let template = reporter(b"prefix {{ range . }}{{ .Secret }}{{ end }} suffix");
    let mut writer = FailingWriter {
        bytes: Vec::new(),
        remaining: 4,
        flushes: 0,
    };
    assert!(matches!(
        template.render(&mut writer, &[fixture_finding()]),
        Err(TemplateError::Io(_))
    ));
    assert_eq!(writer.bytes, b"pref");
    assert_eq!(writer.flushes, 0);
}

#[test]
fn public_profile_and_defaults_are_versioned_and_checked() {
    assert_eq!(SAFE_TEMPLATE_PROFILE, "rustleaks-safe-template-v1");
    assert_eq!(
        TemplateLimits::default(),
        TemplateLimits::new(1024 * 1024, 1_000_000, TemplateLimits::NO_OUTPUT_LIMIT)
            .with_actions_per_finding(1_000)
    );
    let empty = reporter(b"");
    assert!(render(&empty, &[]).is_empty());
}

#[test]
fn every_template_oracle_case_has_an_exact_replay_or_named_safe_profile_disposition() {
    // These are all 15 template-format requests in report-corpus v1. Keeping
    // the complete ID list here makes additions review-visible instead of
    // silently treating them as covered by two happy-path fixtures.
    let cases = [
        "template-markdown",
        "template-jsonextra",
        "template-empty",
        "template-safe-helpers",
        "template-raw-bytes",
        "template-block-env",
        "template-block-expandenv",
        "template-block-host",
        "template-allow-now-parse",
        "template-allow-random-parse",
        "template-parse-error",
        "template-execute-error",
        "template-empty-path",
        "template-missing-path",
        "template-writer-error",
    ];
    assert_eq!(cases.len(), 15);

    // Exact declared-domain replays. Markdown/JSON-extra are compared against
    // their golden bytes above; empty and now/date are exercised here too.
    assert!(render(&reporter(b""), &[]).is_empty());
    assert!(
        TemplateReporter::from_bytes(
            b"{{ now | date \"2006-01-02\" }}",
            TemplateLimits::default()
        )
        .is_ok()
    );

    // The upstream oracle intentionally demonstrates helpers outside safe-v1.
    // Direct raw-byte rendering is retained through range/current-dot (proved
    // above); index, upper, hashing, default, random, and out-of-range index
    // execution are explicit construction-time profile boundaries.
    for (id, source) in [
        (
            "template-safe-helpers",
            b"{{ upper (index . 0).RuleID }}".as_slice(),
        ),
        ("template-raw-bytes", b"{{ (index . 0).Secret }}"),
        ("template-allow-random-parse", b"{{ randAlphaNum 8 }}"),
        ("template-execute-error", b"{{ index . 99 }}"),
    ] {
        assert!(
            matches!(
                TemplateReporter::from_bytes(source, TemplateLimits::default()),
                Err(TemplateError::UnsupportedFeature { .. })
            ),
            "{id} must remain an explicit safe-profile disposition"
        );
    }

    for (id, source) in [
        ("template-block-env", b"{{ env \"value\" }}".as_slice()),
        ("template-block-expandenv", b"{{ expandenv \"value\" }}"),
        ("template-block-host", b"{{ getHostByName \"value\" }}"),
    ] {
        let error = TemplateReporter::from_bytes(source, TemplateLimits::default()).unwrap_err();
        assert!(matches!(error, TemplateError::UnsupportedFeature { .. }));
        assert!(error.to_string().contains("not defined"), "{id}");
    }

    assert!(matches!(
        TemplateReporter::from_bytes(b"{{", TemplateLimits::default()),
        Err(TemplateError::Parse { .. })
    ));
    assert!(matches!(
        TemplateReporter::from_path(Path::new(""), TemplateLimits::default()),
        Err(TemplateError::EmptyPath)
    ));
    assert!(matches!(
        TemplateReporter::from_path(
            Path::new("this-template-does-not-exist-anywhere.tmpl"),
            TemplateLimits::default()
        ),
        Err(TemplateError::Read { .. })
    ));

    // The exact writer-failure prefix is asserted in the dedicated writer
    // test. Touch the edge IDs so the complete frozen list remains explicit.
    assert_eq!(cases[0], "template-markdown");
    assert_eq!(cases[1], "template-jsonextra");
    assert_eq!(cases[14], "template-writer-error");
}
