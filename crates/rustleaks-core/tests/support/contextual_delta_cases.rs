//! Authored positive cases for contextual and residual delimiter additions,
//! shared by `contextual_rule_deltas.rs` and the all-rules precedence test.

pub struct Case {
    pub source: &'static str,
    pub label: &'static str,
    pub secret: String,
    pub path: &'static str,
}

pub fn body(n: usize) -> String {
    "Q7m2Z9v4L1c8R5s0N6b3X".chars().cycle().take(n).collect()
}

pub fn hex(n: usize) -> String {
    "a7f2b9e4c1d80563".chars().cycle().take(n).collect()
}

pub fn uuid() -> &'static str {
    "a7f2b9e4-c1d8-0563-a7f2-b9e4c1d80563"
}

pub fn case(source: &'static str, label: &'static str, secret: String) -> Case {
    Case {
        source,
        label,
        secret,
        path: if source == "hashicorp-tf-password" {
            "synthetic/source.tf"
        } else {
            "synthetic/source.txt"
        },
    }
}

pub fn fixed_cases() -> Vec<Case> {
    vec![
        case("beamer-api-token", "beamer", format!("b_{}", body(44))),
        case(
            "defined-networking-api-token",
            "dnkey",
            format!("dnkey-{}-{}", body(26), body(52)),
        ),
        case("heroku-api-key", "heroku", uuid().into()),
        case("hubspot-api-key", "hubspot", uuid().into()),
        case(
            "mailgun-private-api-token",
            "mailgun",
            format!("key-{}", hex(32)),
        ),
        case(
            "mailgun-signing-key",
            "mailgun",
            format!(
                "{}-a7g2b9h4-h4c1d805",
                "a7g2b9h4c1d80563"
                    .chars()
                    .cycle()
                    .take(32)
                    .collect::<String>()
            ),
        ),
        case("squarespace-access-token", "squarespace", uuid().into()),
        case(
            "typeform-api-token",
            "typeform",
            format!("tfp_{}", body(59)),
        ),
        case(
            "yandex-aws-access-token",
            "yandex",
            format!("YC{}", body(38)),
        ),
    ]
}

pub fn append_yandex_cases(cases: &mut Vec<Case>) {
    for first in [1, 12] {
        for left_padding in ["", "=", "=="] {
            for right_padding in ["", "=", "=="] {
                cases.push(case(
                    "yandex-access-token",
                    "yandex",
                    format!(
                        "t1.{}{left_padding}.{}{right_padding}",
                        body(first),
                        body(86)
                    ),
                ));
            }
        }
    }
    for length in 35..=38 {
        cases.push(case(
            "yandex-api-key",
            "yandex",
            format!("AQVN{}", body(length)),
        ));
    }
}

pub fn cases() -> Vec<Case> {
    let mut cases = fixed_cases();
    for label in ["password", "administrator_login_password"] {
        for length in [8, 9, 10, 20] {
            cases.push(case(
                "hashicorp-tf-password",
                label,
                format!("\"{}\"", body(length)),
            ));
        }
    }
    for role in ["live", "test"] {
        cases.push(case("lob-api-key", "lob", format!("{role}_{}", hex(35))));
    }
    for label in [
        "mailchimp",
        "MailchimpSDK.initialize",
        "MailchimpSDKXinitialize",
        "MailchimpSDKéinitialize",
    ] {
        cases.push(case(
            "mailchimp-api-key",
            label,
            format!("{}-us42", hex(32)),
        ));
    }
    for label in ["okta", "Okta", "OKTA"] {
        cases.push(case("okta-access-token", label, format!("00{}", body(40))));
    }
    for role in ["sandbox", "development", "production"] {
        cases.push(case(
            "plaid-api-token",
            "plaid",
            format!("access-{role}-{}", uuid()),
        ));
    }
    for label in [
        "BUNDLE_GEMS__CONTRIBSYS__COM",
        "BUNDLE_ENTERPRISE__CONTRIBSYS__COM",
    ] {
        cases.push(case(
            "sidekiq-secret",
            label,
            format!("{}:{}", hex(8), hex(8)),
        ));
    }
    for label in [
        "snykkey",
        "snyk_token",
        "snyk-api-key",
        "snyk.oauth.token",
        "snykapitoken",
        "snykoauthkey",
    ] {
        cases.push(case("snyk-api-token", label, uuid().into()));
    }
    for label in ["sonarlogin", "sonar_token", "sonar-login", "sonar.token"] {
        for prefix in ["", "squ_", "sqp_", "sqa_"] {
            cases.push(case(
                "sonar-api-token",
                label,
                format!("{prefix}{}", body(40)),
            ));
        }
    }
    for digits in [5, 16] {
        cases.push(case(
            "telegram-bot-api-token",
            "telegr",
            format!(
                "{}:A{}",
                "1928374650"
                    .chars()
                    .cycle()
                    .take(digits)
                    .collect::<String>(),
                body(34)
            ),
        ));
    }
    append_yandex_cases(&mut cases);
    cases
}

/// Residual vertical-tab companions: the source name and one token.
pub fn residual_vt_tokens() -> Vec<(&'static str, String)> {
    [
        (
            "anthropic-api-key",
            "sk-ant-api03-",
            "AA",
            93,
            "Q7m2Z9v4L1c8R5s0N6b3X",
        ),
        (
            "anthropic-admin-api-key",
            "sk-ant-admin01-",
            "AA",
            93,
            "Q7m2Z9v4L1c8R5s0N6b3X",
        ),
        (
            "digitalocean-refresh-token",
            "dor_v1_",
            "",
            64,
            "a7f2b9e4c1d80563",
        ),
    ]
    .into_iter()
    .map(|(source, prefix, tail, len, alphabet)| {
        let body = alphabet.chars().cycle().take(len).collect::<String>();
        (source, format!("{prefix}{body}{tail}"))
    })
    .collect()
}

/// Old `OpenAI` token shapes that the legacy delimiter rule reports.
pub fn legacy_openai_tokens() -> Vec<String> {
    let mut tokens = vec![format!("sk-{}T3BlbkFJ{}", body(20), body(20))];
    for role in ["proj", "svcacct", "admin"] {
        for left in [58, 74] {
            for right in [58, 74] {
                tokens.push(format!("sk-{role}-{}T3BlbkFJ{}", body(left), body(right)));
            }
        }
    }
    tokens
}

/// One positive case: name, owning rule, input, file path, secret, and the
/// byte offset of the secret in the input.
pub type Positive = (String, String, String, &'static str, String, usize);

/// Positives in the layouts that `contextual_rule_deltas.rs` checks: each
/// case as `label=secret` with an escaped quote (the delimiter rule) and with
/// a vertical tab before `=` (the context rule), each residual token before a
/// vertical tab, and each old `OpenAI` token before an escaped quote.
pub fn positives() -> Vec<Positive> {
    let mut positives = Vec::new();
    for case in cases() {
        for (pre, kind) in [("", "delimiter"), ("\u{b}", "context-vt")] {
            let rule = format!("rustleaks.{}-{kind}", case.source);
            positives.push((
                format!("{rule}/{}", positives.len()),
                rule,
                format!("lead\nx {}{pre}={}\\\"", case.label, case.secret),
                case.path,
                case.secret.clone(),
                7 + case.label.len() + pre.len() + 1,
            ));
        }
    }
    for (source, token) in residual_vt_tokens() {
        let rule = format!("rustleaks.{source}-vt");
        positives.push((
            format!("{rule}/{}", positives.len()),
            rule,
            format!("{token}\u{b}"),
            "source.txt",
            token,
            0,
        ));
    }
    for token in legacy_openai_tokens() {
        let rule = "rustleaks.openai-api-key-legacy-delimiter".to_owned();
        positives.push((
            format!("{rule}/{}", positives.len()),
            rule,
            format!("{token}\\\""),
            "source.txt",
            token,
            0,
        ));
    }
    positives
}
