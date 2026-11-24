//! Authored positive cases for `rustleaks-providers-v1` rules, shared by
//! `provider_rules.rs` and the all-rules precedence test.

// These bounds are independently specified detector scopes, not read from the
// configuration under test. All values are synthetic and are never validated.
pub const CASES: [(&str, &str, usize); 5] = [
    ("rustleaks.groq-api-key", "gsk_", 52),
    ("rustleaks.cerebras-api-key", "csk-", 48),
    ("rustleaks.replicate-api-token", "r8_", 37),
    ("rustleaks.nvidia-api-key", "nvapi-", 60),
    ("rustleaks.nvidia-api-key", "nvapi-", 70),
];

pub fn body(length: usize) -> String {
    "Q7m2Z9v4L1c8R5s0N6b3X"
        .chars()
        .cycle()
        .take(length)
        .collect()
}

pub fn token(prefix: &str, length: usize) -> String {
    format!("{prefix}{}", body(length))
}

// These companion expectations are independently specified from the pinned
// source grammars. Physical source coordinates are not Finding::location:
// Fragment::new starts at line 0, and columns count from the LF before the
// line.
pub const ESCAPED_CASES: [(&str, &str, &str, usize, &str); 3] = [
    (
        "rustleaks.anthropic-api-key-escaped",
        "anthropic-api-key",
        "sk-ant-api03-",
        93,
        "AA",
    ),
    (
        "rustleaks.anthropic-admin-api-key-escaped",
        "anthropic-admin-api-key",
        "sk-ant-admin01-",
        93,
        "AA",
    ),
    (
        "rustleaks.digitalocean-refresh-token-escaped",
        "digitalocean-refresh-token",
        "dor_v1_",
        64,
        "",
    ),
];

pub fn companion_body(prefix: &str, length: usize) -> String {
    if prefix == "dor_v1_" {
        "a7f2b9e4c1d80563".chars().cycle().take(length).collect()
    } else {
        body(length)
    }
}

pub fn openai(role: &str, left: usize, right: usize) -> String {
    format!("sk-{role}-{}T3BlbkFJ{}", body(left), body(right))
}

pub fn companion_samples() -> Vec<(&'static str, String, &'static str)> {
    let mut samples: Vec<_> = ESCAPED_CASES
        .into_iter()
        .map(|(id, _, prefix, length, tail)| {
            (
                id,
                format!("{prefix}{}{tail}", companion_body(prefix, length)),
                "\\\"",
            )
        })
        .collect();
    samples.push((
        "rustleaks.openai-api-key-20-segment",
        openai("proj", 20, 20),
        ";",
    ));
    samples.push(("rustleaks.flyio-flyv1", format!("FlyV1 {}", body(100)), ";"));
    samples
}

// Distinct standalone provider forms selected from the pinned MIT source.
// Lengths and expected roles are authored independently of the pack TOML.
pub const STANDALONE_CASES: [(&str, &str, usize, usize, bool); 6] = [
    ("rustleaks.cloudsmith-api-key", "csa_", 36, 36, false),
    ("rustleaks.minimax-api-key", "sk-api-", 119, 119, true),
    ("rustleaks.posthog-personal-api-key", "phx_", 41, 49, true),
    (
        "rustleaks.figma-personal-access-token",
        "figd_",
        38,
        42,
        true,
    ),
    ("rustleaks.togetherai-api-key", "tgp_v1_", 43, 43, true),
    ("rustleaks.gcp-gemini-api", "AQ.Ab8RN6", 44, 44, false),
];

pub fn standalone_secret(prefix: &str, length: usize) -> String {
    if prefix == "csa_" {
        let hex: String = "a7f2b9e4c1d80563".chars().cycle().take(30).collect();
        format!("{prefix}{hex}{}", body(length - 30))
    } else {
        token(prefix, length)
    }
}

// Expected syntax and role scopes authored from reviewed source definitions.
// These cases deliberately distinguish source matches from provider validity.
pub struct FollowupCase {
    pub id: &'static str,
    pub context: &'static str,
    pub secret: String,
    pub suffix: &'static str,
    pub folded: bool,
    pub contextual: bool,
}

pub fn hex_body(length: usize) -> String {
    "a7f2b9e4c1d80563".chars().cycle().take(length).collect()
}

pub fn contextual_followup_cases() -> Vec<FollowupCase> {
    let contexts = [
        (
            "checkout-secret-key",
            "checkout",
            format!(
                "sk_{}-{}-{}-{}-{}",
                hex_body(8),
                hex_body(4),
                hex_body(4),
                hex_body(4),
                hex_body(12)
            ),
        ),
        ("crates-io-api-key", "crates.io", format!("cio{}", body(32))),
        ("cursor-api-key", "cursor", format!("key_{}", hex_body(64))),
        ("databento-api-key", "databento", format!("db-{}", body(29))),
        (
            "elevenlabs-api-key",
            "elevenlabs",
            format!("sk_{}", hex_body(48)),
        ),
        (
            "figma-personal-access-header-token",
            "x-figma-token",
            format!(
                "{}-{}-{}-{}-{}-{}",
                hex_body(4),
                hex_body(8),
                hex_body(4),
                hex_body(4),
                hex_body(4),
                hex_body(12)
            ),
        ),
        (
            "ollama-api-key",
            "ollama",
            format!("{}.{}", hex_body(32), body(24)),
        ),
        (
            "polymarket-private-key",
            "poly_private_key",
            format!("0x{}", hex_body(64)),
        ),
        (
            "stability-ai-api-key",
            "stability",
            format!("sk-{}", body(48)),
        ),
    ];
    contexts
        .into_iter()
        .map(|(id, context, secret)| FollowupCase {
            id: match id {
                "checkout-secret-key" => "rustleaks.checkout-secret-key",
                "crates-io-api-key" => "rustleaks.crates-io-api-key",
                "cursor-api-key" => "rustleaks.cursor-api-key",
                "databento-api-key" => "rustleaks.databento-api-key",
                "elevenlabs-api-key" => "rustleaks.elevenlabs-api-key",
                "figma-personal-access-header-token" => {
                    "rustleaks.figma-personal-access-header-token"
                }
                "ollama-api-key" => "rustleaks.ollama-api-key",
                "polymarket-private-key" => "rustleaks.polymarket-private-key",
                "stability-ai-api-key" => "rustleaks.stability-ai-api-key",
                _ => unreachable!(),
            },
            context,
            secret,
            suffix: ";",
            folded: id != "polymarket-private-key",
            contextual: true,
        })
        .collect()
}

pub fn followup_cases() -> Vec<FollowupCase> {
    let mut cases = contextual_followup_cases();
    for (id, secret, suffix) in [
        (
            "rustleaks.slack-session-cookie",
            format!("xoxd-{}", body(100)),
            "!",
        ),
        (
            "rustleaks.slack-session-token",
            format!("xoxc-174285963-963852741-582716349-{}", hex_body(64)),
            "",
        ),
        (
            "rustleaks.circleci-project-token",
            format!("CCIPRJ_{}_{}", body(22), hex_body(40)),
            "",
        ),
        (
            "rustleaks.deno-organization-token",
            format!("ddo_{}", body(36)),
            "",
        ),
        ("rustleaks.xai-api-key-80", format!("xai-{}", body(80)), ""),
        (
            "rustleaks.postman-collection-token",
            format!("PMAT-{}", body(26)),
            "",
        ),
    ] {
        cases.push(FollowupCase {
            id,
            context: "",
            secret,
            suffix,
            folded: false,
            contextual: false,
        });
    }
    cases
}

pub fn followup_text(case: &FollowupCase) -> String {
    if case.contextual {
        format!("{}={}", case.context, case.secret)
    } else {
        case.secret.clone()
    }
}

pub const BYTE_CASES: [(&str, &str, usize, usize); 6] = [
    (
        "rustleaks.dockerhub-personal-access-token",
        "dckr_pat_",
        27,
        27,
    ),
    (
        "rustleaks.dockerhub-organization-access-token",
        "dckr_oat_",
        32,
        32,
    ),
    ("rustleaks.neon-api-key", "napi_", 64, 64),
    ("rustleaks.render-api-key", "rnd_", 28, 28),
    ("rustleaks.deno-account-token", "ddp_", 36, 36),
    ("rustleaks.apify-api-token", "apify_api_", 34, 38),
];

pub const ALIBABA: &str = "rustleaks.alibaba-access-key-id-boundary";
pub const SLACK_ACCESS: &str = "rustleaks.slack-config-access-token-166";
pub const XAI: &str = "rustleaks.xai-api-key-delimiter";

/// Alibaba `LTAI` and `length` ASCII alphanumerics.
pub fn alibaba_secret(length: usize) -> String {
    format!("LTAI{}", body(length))
}

/// Slack `xoxe.xoxp-`, the given digits, `-` and a 166-byte body.
pub fn slack_access_secret(digits: &str) -> String {
    format!("xoxe.xoxp-{digits}-{}", body(166))
}

/// xAI `xai-` and `length` body bytes.
pub fn xai_secret(length: usize) -> String {
    format!("xai-{}", body(length))
}

/// One positive case: name, owning rule, input, file path, secret, and the
/// byte offset of the secret in the input.
pub type Positive = (String, String, String, &'static str, String, usize);

/// One positive for each case above, in the layout that `provider_rules.rs`
/// checks: `lead\nx `, then the case text and its suffix.
pub fn positives() -> Vec<Positive> {
    let mut positives = Vec::new();
    let mut push = |rule: &str, text: String, secret: String, suffix: &str| {
        let start = 7 + text.len() - secret.len();
        let name = format!("{rule}/{}", positives.len());
        positives.push((
            name,
            rule.to_owned(),
            format!("lead\nx {text}{suffix}"),
            "",
            secret,
            start,
        ));
    };
    for (id, prefix, length) in CASES {
        push(id, token(prefix, length), token(prefix, length), ";");
    }
    for (id, secret, suffix) in companion_samples() {
        push(id, secret.clone(), secret, suffix);
    }
    for (id, prefix, minimum, _, _) in STANDALONE_CASES {
        let secret = standalone_secret(prefix, minimum);
        push(id, secret.clone(), secret, ";");
    }
    for case in followup_cases() {
        push(
            case.id,
            followup_text(&case),
            case.secret.clone(),
            case.suffix,
        );
    }
    for (id, prefix, minimum, _) in BYTE_CASES {
        push(id, token(prefix, minimum), token(prefix, minimum), ";");
    }
    // The widened rules, in the `key=` layout that `provider_rules.rs` uses.
    for (id, secret, tail) in [
        (ALIBABA, alibaba_secret(17), "\n"),
        (SLACK_ACCESS, slack_access_secret("1"), "\n"),
        (XAI, xai_secret(70), ";"),
    ] {
        positives.push((
            format!("{id}/{}", positives.len()),
            id.to_owned(),
            format!("key={secret}{tail}"),
            "",
            secret,
            4,
        ));
    }
    positives
}
