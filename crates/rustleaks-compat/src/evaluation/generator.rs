use super::model::{CONFIG_SHA256, Case, Corpus, PROFILE, Positive, Span, fingerprint};

const GITHUB: &[u8] = b"ghp_Q7m2Nz4T9x6W1c5V8b3L0r4D7f2H9j6K1p5S";
const AWS: &[u8] = b"AKIAQWERTYUIOPASDFGH";
const GENERIC: &[u8] = b"Q7m2Nz4T9x6W1c5V8b3L0r4D7f2H9j6K";
const PAIRED: &[u8] = b"L8p4V1k7N2c6R9s3T5w0X8y4Z6b2D7f9";
const UNKNOWN: &[u8] = b"M2r8C4v6B1n9H5j3K7l0P2q8S4t6W1x9";

pub(super) fn case(id: &str, split: &str, stratum: &str, input: Vec<u8>, rules: &[&str]) -> Case {
    Case {
        id: id.into(),
        leakage_group: id.into(),
        split: split.into(),
        stratum: stratum.into(),
        rationale: "Deterministic synthetic content; labels record intended secret or benign roles, not live credential validity.".into(),
        content_fnv1a64: fingerprint(&input),
        input,
        path: "settings.conf".into(),
        selected_rules: rules.iter().map(|value| (*value).into()).collect(),
        positives: Vec::new(),
        negative_regions: Vec::new(),
        unknown_regions: Vec::new(),
        decode_depth: 0,
        max_work_units: 100_000,
    }
}

pub(super) fn label(case: &mut Case, needle: &[u8], family: &str, rule: &str) {
    for (start, window) in case.input.windows(needle.len()).enumerate() {
        if window == needle {
            case.positives.push(Positive {
                span: Span {
                    start,
                    end: start + needle.len(),
                },
                expected_secret: needle.to_vec(),
                family: family.into(),
                rule_ids: vec![rule.into()],
            });
        }
    }
}

pub(super) fn around(prefix: &[u8], secret: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, secret, suffix].concat()
}

fn negatives(case: &mut Case) {
    let mut reserved: Vec<_> = case.positives.iter().map(|value| value.span).collect();
    reserved.extend(&case.unknown_regions);
    reserved.sort_unstable();
    let mut start = 0;
    for span in reserved {
        if start < span.start {
            case.negative_regions.push(Span {
                start,
                end: span.start,
            });
        }
        start = span.end;
    }
    if start < case.input.len() {
        case.negative_regions.push(Span {
            start,
            end: case.input.len(),
        });
    }
}

#[allow(clippy::too_many_lines)] // Keep the reviewed synthetic case catalog together.
pub(super) fn corpus() -> Corpus {
    let mut cases = Vec::new();
    for (id, prefix, suffix, path) in [
        (
            "github-raw",
            b"".as_slice(),
            b"".as_slice(),
            "settings.conf",
        ),
        ("github-assignment", b"api_key = '", b"'\n", "settings.conf"),
        ("github-invalid-utf8", b"\xff\0", b"\xfe\n", "settings.conf"),
        ("github-documentation", b"Example: ", b"\n", "README.md"),
        ("github-vendor", b"key = '", b"'\n", "vendor/settings.conf"),
    ] {
        let mut value = case(
            id,
            "holdout",
            "provider-token",
            around(prefix, GITHUB, suffix),
            &["github-pat"],
        );
        value.path = path.into();
        value.leakage_group = "github-prefix".into();
        label(&mut value, GITHUB, "github-pat", "github-pat");
        cases.push(value);
    }
    let mut repeated = case(
        "github-repeated-occurrences",
        "holdout",
        "duplicates",
        [GITHUB, b"\n", GITHUB, b"\n"].concat(),
        &["github-pat"],
    );
    repeated.leakage_group = "github-prefix".into();
    label(&mut repeated, GITHUB, "github-pat", "github-pat");
    cases.push(repeated);

    let mut overlap = case(
        "github-generic-overlap",
        "holdout",
        "overlapping-rules",
        around(b"token='", GITHUB, b"'"),
        &["github-pat", "generic-api-key"],
    );
    overlap.leakage_group = "github-prefix".into();
    label(&mut overlap, GITHUB, "github-pat", "github-pat");
    cases.push(overlap);

    let encoded: Vec<u8> = GITHUB
        .iter()
        .flat_map(|byte| format!("%{byte:02X}").into_bytes())
        .collect();
    let mut encoded_case = case(
        "github-percent-encoded",
        "holdout",
        "encoded",
        around(b"value=", &encoded, b"\n"),
        &["github-pat"],
    );
    encoded_case.leakage_group = "github-prefix".into();
    encoded_case.decode_depth = 1;
    label(&mut encoded_case, &encoded, "github-pat", "github-pat");
    encoded_case.positives[0].expected_secret = GITHUB.to_vec();
    cases.push(encoded_case);

    let mut aws = case(
        "aws-paired-fields",
        "holdout",
        "paired-credentials",
        [
            b"access_id='".as_slice(),
            AWS,
            b"'\nsecret='",
            PAIRED,
            b"'\n",
        ]
        .concat(),
        &["aws-access-token", "generic-api-key"],
    );
    aws.leakage_group = "aws-pair".into();
    label(&mut aws, AWS, "aws-access-id", "aws-access-token");
    label(&mut aws, PAIRED, "generic-secret", "generic-api-key");
    cases.push(aws);

    let mut generic = case(
        "generic-secret-assignment",
        "tune",
        "generic-credential",
        around(b"secret='", GENERIC, b"'\n"),
        &["generic-api-key"],
    );
    generic.leakage_group = "generic-assignment".into();
    label(&mut generic, GENERIC, "generic-secret", "generic-api-key");
    cases.push(generic);

    let private = [
        b"-----BEGIN PRIVATE KEY-----\n".as_slice(),
        b"Q7m2Nz4T9x6W1c5V8b3L0r4D7f2H9j6K1p5S\n",
        b"L8k3P0s6N9v2T5w7X1z4B6c8D0e2F4g6H8i0\n",
        b"-----END PRIVATE KEY-----",
    ]
    .concat();
    let mut key = case(
        "multiline-private-key-shape",
        "holdout",
        "multiline",
        private.clone(),
        &["private-key"],
    );
    key.rationale = "Synthetic private-key-shaped block, intentionally secret-bearing test material; not a usable cryptographic key.".into();
    label(&mut key, &private, "private-key", "private-key");
    cases.push(key);

    for (id, text, rule) in [
        (
            "negative-placeholder",
            "api_key='REPLACE_WITH_VALUE'\n",
            "generic-api-key",
        ),
        (
            "negative-ordinary-words",
            "password='ordinary words in documentation'\n",
            "generic-api-key",
        ),
        (
            "negative-uuid",
            "request_id='57e9d0a2-5e1b-4a6c-8f02-c9a01d3297f4'\n",
            "generic-api-key",
        ),
        (
            "negative-hash",
            "sha256='e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf'\n",
            "generic-api-key",
        ),
        (
            "negative-near-miss",
            "prefix ghp_short_suffix\n",
            "github-pat",
        ),
        (
            "negative-build-identifier",
            "build_id='Q7m2Nz4T9x6W1c5V8b3L0r4D7f2H9j6K'\n",
            "generic-api-key",
        ),
        (
            "negative-secret-shaped-id",
            "api_key='57e9d0a2-5e1b-4a6c-8f02-c9a01d3297f4'\n",
            "generic-api-key",
        ),
    ] {
        let mut value = case(
            id,
            "tune",
            "reviewed-benign",
            text.as_bytes().to_vec(),
            &[rule],
        );
        value.leakage_group = "benign-identifiers".into();
        value.rationale = "Synthetic benign identifier or placeholder by construction, including an intentionally misleading field name; a match is a false alert in this corpus.".into();
        cases.push(value);
    }
    let mut unknown = case(
        "unknown-role",
        "holdout",
        "unadjudicated",
        around(b"token='", UNKNOWN, b"'\n"),
        &["generic-api-key"],
    );
    unknown.leakage_group = "unknown-assignment".into();
    unknown.rationale = "Synthetic ambiguous field role intentionally left unadjudicated; alerts on the value are unknown, not false positives.".into();
    unknown.unknown_regions = vec![Span {
        start: 7,
        end: 7 + UNKNOWN.len(),
    }];
    cases.push(unknown);
    cases.extend(super::pilot::cases());
    for value in &mut cases {
        negatives(value);
    }
    Corpus {
        schema_version: 1,
        generator: "rustleaks-quality-v1".into(),
        generator_source_fnv1a64: source_fingerprint(),
        license: "MIT".into(),
        provenance: "First-party deterministic synthetic cases. No live or external credential corpus; activity and issuer validity are not verified.".into(),
        intended_population: "Small synthetic structural and labeling controls, not a sample of deployments or a provider-validity benchmark.".into(),
        profile: PROFILE.into(),
        default_config_sha256: CONFIG_SHA256.into(),
        cases,
    }
}

pub(super) fn source_fingerprint() -> String {
    fingerprint(
        &[
            include_bytes!("generator.rs").as_slice(),
            include_bytes!("pilot.rs").as_slice(),
        ]
        .concat(),
    )
}
