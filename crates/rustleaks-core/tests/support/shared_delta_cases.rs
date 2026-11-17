//! Authored positive cases for shared-prefix delimiter additions, shared by
//! `shared_rule_deltas.rs` and the all-rules precedence test.

#[derive(Clone, Copy)]
pub struct Case {
    pub id: &'static str,
    pub prefix: &'static str,
    pub min: usize,
    pub max: usize,
    pub tail: &'static str,
    pub alphabet: &'static str,
    pub context: &'static str,
}

pub const CASES: [Case; 28] = [
    Case {
        id: "rustleaks.aws-amazon-bedrock-api-key-long-lived-delimiter",
        prefix: "ABSK",
        min: 109,
        max: 269,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.digitalocean-access-token-delimiter",
        prefix: "doo_v1_",
        min: 64,
        max: 64,
        tail: "",
        alphabet: "a7f2b9e4c1d80563",
        context: "",
    },
    Case {
        id: "rustleaks.gcp-api-key-delimiter",
        prefix: "AIza",
        min: 35,
        max: 35,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.huggingface-access-token-delimiter",
        prefix: "hf_",
        min: 34,
        max: 34,
        tail: "",
        alphabet: "QmZvLcRsNbXhYpTfJgWd",
        context: "",
    },
    Case {
        id: "rustleaks.huggingface-organization-api-token-delimiter",
        prefix: "api_org_",
        min: 34,
        max: 34,
        tail: "",
        alphabet: "QmZvLcRsNbXhYpTfJgWd",
        context: "",
    },
    Case {
        id: "rustleaks.infracost-api-token-delimiter",
        prefix: "ico-",
        min: 32,
        max: 32,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.intra42-client-secret-delimiter",
        prefix: "s-s4t2ud-",
        min: 64,
        max: 64,
        tail: "",
        alphabet: "a7f2b9e4c1d80563",
        context: "",
    },
    Case {
        id: "rustleaks.intra42-client-secret-delimiter",
        prefix: "s-s4t2af-",
        min: 64,
        max: 64,
        tail: "",
        alphabet: "a7f2b9e4c1d80563",
        context: "",
    },
    Case {
        id: "rustleaks.maxmind-license-key-delimiter",
        prefix: "Q7m2Z9_",
        min: 29,
        max: 29,
        tail: "_mmk",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.notion-api-token-delimiter",
        prefix: "ntn_19283746501",
        min: 35,
        max: 35,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.octopus-deploy-api-key-delimiter",
        prefix: "API-",
        min: 26,
        max: 26,
        tail: "",
        alphabet: "Q7M2Z9V4L1C8R5S0N6B3X",
        context: "",
    },
    Case {
        id: "rustleaks.planetscale-oauth-token-delimiter",
        prefix: "pscale_oauth_",
        min: 32,
        max: 64,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.planetscale-password-delimiter",
        prefix: "pscale_pw_",
        min: 32,
        max: 64,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.prefect-api-token-delimiter",
        prefix: "pnu_",
        min: 36,
        max: 36,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.pulumi-api-token-delimiter",
        prefix: "pul-",
        min: 40,
        max: 40,
        tail: "",
        alphabet: "a7f2b9e4c1d80563",
        context: "",
    },
    Case {
        id: "rustleaks.readme-api-token-delimiter",
        prefix: "rdme_",
        min: 70,
        max: 70,
        tail: "",
        alphabet: "q7m2z9v4l1c8r5s0n6b3x",
        context: "",
    },
    Case {
        id: "rustleaks.rubygems-api-token-delimiter",
        prefix: "rubygems_",
        min: 48,
        max: 48,
        tail: "",
        alphabet: "a7f2b9e4c1d80563",
        context: "",
    },
    Case {
        id: "rustleaks.scalingo-api-token-delimiter",
        prefix: "tk-us-",
        min: 48,
        max: 48,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.settlemint-application-access-token-delimiter",
        prefix: "sm_aat_",
        min: 16,
        max: 16,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.settlemint-personal-access-token-delimiter",
        prefix: "sm_pat_",
        min: 16,
        max: 16,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.settlemint-service-access-token-delimiter",
        prefix: "sm_sat_",
        min: 16,
        max: 16,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.shippo-api-token-delimiter",
        prefix: "shippo_live_",
        min: 40,
        max: 40,
        tail: "",
        alphabet: "a7f2b9e4c1d80563",
        context: "",
    },
    Case {
        id: "rustleaks.shippo-api-token-delimiter",
        prefix: "shippo_test_",
        min: 40,
        max: 40,
        tail: "",
        alphabet: "a7f2b9e4c1d80563",
        context: "",
    },
    Case {
        id: "rustleaks.square-access-token-delimiter",
        prefix: "sq0atp-",
        min: 22,
        max: 60,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.square-access-token-delimiter",
        prefix: "EAAA",
        min: 22,
        max: 60,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.vault-batch-token-delimiter",
        prefix: "hvb.",
        min: 138,
        max: 300,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.vault-service-token-delimiter",
        prefix: "hvs.",
        min: 90,
        max: 120,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "",
    },
    Case {
        id: "rustleaks.vault-service-token-delimiter",
        prefix: "s.",
        min: 24,
        max: 24,
        tail: "",
        alphabet: "Q7m2Z9v4L1c8R5s0N6b3X",
        context: "vault ",
    },
];

pub fn secret(case: Case, length: usize) -> String {
    let body: String = case.alphabet.chars().cycle().take(length).collect();
    format!("{}{body}{}", case.prefix, case.tail)
}

/// One positive case: name, owning rule, input, file path, secret, and the
/// byte offset of the secret in the input.
pub type Positive = (String, String, String, &'static str, String, usize);

/// One positive for each case at its shortest length, in the layout that
/// `shared_rule_deltas.rs` checks: `lead\nx `, any context, the secret and
/// an escaped quote.
pub fn positives() -> Vec<Positive> {
    CASES
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let secret = secret(*case, case.min);
            (
                format!("{}/{index}", case.id),
                case.id.to_owned(),
                format!("lead\nx {}{secret}\\'", case.context),
                "",
                secret,
                7 + case.context.len(),
            )
        })
        .collect()
}
