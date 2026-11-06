//! Independent intent labels for the three-family native rules pilot.

use super::generator::{around, case, label};
use super::model::{Case, fingerprint};

const SERVICE_RULE: &str = "rustleaks.azure-servicebus-key";
const APP_RULE: &str = "rustleaks.azure-app-configuration-key";
const MONGO_RULE: &str = "rustleaks.mongodb-password";
const SERVICE_KEY: &str = "B7p4K9x2N6v1Q8s3T5w0Y4z7A2c6D9f1G8h3J5k0L4M=";
const APP_KEY: &str = "C8q5L0y3O7w2R9t4U6x1Z5a8B3d7E0g2H9i4K6l1M5Q=";
const MONGO_PASSWORD: &str = "r8!Qw2-Db9";

// These formats, roles and labels are specified from provider documentation,
// not produced from matching rules. Related variants stay in one split.
pub(super) fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    azure_cases(&mut cases);
    mongo_cases(&mut cases);
    gaps(&mut cases);
    negatives(&mut cases);
    cases
}

fn positive(id: &str, input: Vec<u8>, secret: &[u8], family: &str, rule: &str) -> Case {
    let mut value = case(
        id,
        "holdout",
        "native-pilot",
        input,
        &[rule, "generic-api-key"],
    );
    value.leakage_group = family.into();
    value.rationale = "First-party synthetic credential role and byte extent, independently specified from primary provider formats. Not an active credential or deployment sample.".into();
    label(&mut value, secret, family, rule);
    value
}

#[allow(clippy::too_many_lines)] // Keep each provider format catalog together.
fn azure_cases(cases: &mut Vec<Case>) {
    for (family, rule, fields, secret) in [
        (
            "azure-servicebus",
            SERVICE_RULE,
            [
                "Endpoint=sb://synthetic-bus.servicebus.windows.net/".to_owned(),
                "SharedAccessKeyName=synthetic-policy".to_owned(),
                format!("SharedAccessKey={SERVICE_KEY}"),
            ],
            SERVICE_KEY,
        ),
        (
            "azure-app-configuration",
            APP_RULE,
            [
                "Endpoint=https://synthetic-store.azconfig.io".to_owned(),
                "Id=synthetic-id:read".to_owned(),
                format!("Secret={APP_KEY}"),
            ],
            APP_KEY,
        ),
    ] {
        for (index, order) in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ]
        .into_iter()
        .enumerate()
        {
            let input = format!(
                "config=\"{};{};{}\"\n",
                fields[order[0]], fields[order[1]], fields[order[2]]
            );
            cases.push(positive(
                &format!("{family}-order-{index}"),
                input.into_bytes(),
                secret.as_bytes(),
                family,
                rule,
            ));
        }
        let text = fields.join(";");
        cases.push(positive(
            &format!("{family}-invalid-bytes"),
            around(b"\xff\0\"", text.as_bytes(), b"\"\xfe"),
            secret.as_bytes(),
            family,
            rule,
        ));
        let spaced = fields
            .iter()
            .map(|field| field.replacen('=', " = \t", 1))
            .collect::<Vec<_>>()
            .join(" ;\t");
        cases.push(positive(
            &format!("{family}-field-spacing"),
            spaced.into_bytes(),
            secret.as_bytes(),
            family,
            rule,
        ));
        let repeated = format!("{text}\n{text}\n");
        cases.push(positive(
            &format!("{family}-repeated"),
            repeated.into_bytes(),
            secret.as_bytes(),
            family,
            rule,
        ));
        let encoded: Vec<u8> = text
            .bytes()
            .flat_map(|byte| format!("%{byte:02X}").into_bytes())
            .collect();
        let encoded_secret: Vec<u8> = secret
            .bytes()
            .flat_map(|byte| format!("%{byte:02X}").into_bytes())
            .collect();
        let mut value = positive(
            &format!("{family}-percent-envelope"),
            around(b"\"", &encoded, b"\""),
            &encoded_secret,
            family,
            rule,
        );
        value.positives[0].expected_secret = secret.as_bytes().to_vec();
        value.decode_depth = 1;
        cases.push(value);
    }
    let event_hub = format!(
        "Endpoint=sb://synthetic-hub.servicebus.windows.net/;EntityPath=synthetic-events;SharedAccessKeyName=send-policy;SharedAccessKey={SERVICE_KEY}"
    );
    cases.push(positive(
        "azure-eventhub-entity-path",
        event_hub.into_bytes(),
        SERVICE_KEY.as_bytes(),
        "azure-servicebus",
        SERVICE_RULE,
    ));
}

fn mongo_cases(cases: &mut Vec<Case>) {
    for (id, text, secret) in [
        (
            "mongodb-standard",
            format!("mongodb://synthetic:{MONGO_PASSWORD}@db.example.invalid:27017/app"),
            MONGO_PASSWORD,
        ),
        (
            "mongodb-srv",
            format!("mongodb+srv://synthetic:{MONGO_PASSWORD}@cluster.example.invalid/app"),
            MONGO_PASSWORD,
        ),
        (
            "mongodb-host-list",
            format!(
                "mongodb://synthetic:{MONGO_PASSWORD}@one.example.invalid:27017,two.example.invalid:27018/?replicaSet=rs"
            ),
            MONGO_PASSWORD,
        ),
        (
            "mongodb-percent-userinfo",
            "mongodb://synthetic%40user:r8%40Qw2%3ADb9@db.example.invalid/app".to_owned(),
            "r8%40Qw2%3ADb9",
        ),
        (
            "mongodb-short-password",
            "mongodb://synthetic:m7!@db.example.invalid/".to_owned(),
            "m7!",
        ),
    ] {
        cases.push(positive(
            id,
            text.into_bytes(),
            secret.as_bytes(),
            "mongodb-uri",
            MONGO_RULE,
        ));
    }
    let provider = "ghp_Q7m2Nz4T9x6W1c5V8b3L0r4D7f2H9j6K1p5S";
    let mut overlap = positive(
        "mongodb-provider-overlap",
        format!("mongodb://synthetic:{provider}@db.example.invalid/").into_bytes(),
        provider.as_bytes(),
        "mongodb-uri",
        MONGO_RULE,
    );
    overlap.stratum = "native-specific-overlap".into();
    overlap.positives[0].rule_ids.push("github-pat".into());
    overlap.selected_rules.push("github-pat".into());
    overlap.rationale = "A synthetic database password also has a provider-token format. Both specific attributions are useful, so one additional alert at the same occurrence is retained and measured explicitly.".into();
    cases.push(overlap);
    let raw = format!("mongodb://synthetic:{MONGO_PASSWORD}@db.example.invalid/");
    cases.push(positive(
        "mongodb-invalid-bytes",
        around(b"\xff\0\"", raw.as_bytes(), b"\"\xfe"),
        MONGO_PASSWORD.as_bytes(),
        "mongodb-uri",
        MONGO_RULE,
    ));
    cases.push(positive(
        "mongodb-repeated",
        format!("{raw}\n{raw}\n").into_bytes(),
        MONGO_PASSWORD.as_bytes(),
        "mongodb-uri",
        MONGO_RULE,
    ));
    let encoded: Vec<u8> = raw
        .bytes()
        .flat_map(|byte| format!("%{byte:02X}").into_bytes())
        .collect();
    let encoded_secret: Vec<u8> = MONGO_PASSWORD
        .bytes()
        .flat_map(|byte| format!("%{byte:02X}").into_bytes())
        .collect();
    let mut value = positive(
        "mongodb-percent-envelope",
        encoded,
        &encoded_secret,
        "mongodb-uri",
        MONGO_RULE,
    );
    value.positives[0].expected_secret = MONGO_PASSWORD.as_bytes().to_vec();
    value.decode_depth = 1;
    cases.push(value);
}

#[allow(clippy::too_many_lines)] // Keep reviewed near misses together for auditing.
fn negatives(cases: &mut Vec<Case>) {
    // Generate the low-entropy placeholder used by both negative controls.
    let repeated_key = format!("{}=", "A".repeat(43));
    let service_placeholder = format!(
        "Endpoint=sb://namespace.servicebus.windows.net/;SharedAccessKeyName=policy;SharedAccessKey={repeated_key}"
    );
    let app_placeholder =
        format!("Endpoint=https://store.azconfig.io;Id=synthetic;Secret={repeated_key}");
    for (id, text, family, rule) in [
        (
            "servicebus-template",
            "Endpoint=sb://namespace.servicebus.windows.net/;SharedAccessKeyName=policy;SharedAccessKey=<KEY>",
            "azure-servicebus",
            SERVICE_RULE,
        ),
        (
            "servicebus-empty",
            "Endpoint=sb://namespace.servicebus.windows.net/;SharedAccessKeyName=policy;SharedAccessKey=",
            "azure-servicebus",
            SERVICE_RULE,
        ),
        (
            "servicebus-short",
            "Endpoint=sb://namespace.servicebus.windows.net/;SharedAccessKeyName=policy;SharedAccessKey=short",
            "azure-servicebus",
            SERVICE_RULE,
        ),
        (
            "servicebus-template-fields",
            "Endpoint=${ENDPOINT};SharedAccessKeyName=${NAME};SharedAccessKey=${KEY}",
            "azure-servicebus",
            SERVICE_RULE,
        ),
        (
            "appconfiguration-template",
            "Endpoint=https://store.azconfig.io;Id=synthetic;Secret=<SECRET>",
            "azure-app-configuration",
            APP_RULE,
        ),
        (
            "appconfiguration-empty",
            "Endpoint=https://store.azconfig.io;Id=synthetic;Secret=",
            "azure-app-configuration",
            APP_RULE,
        ),
        (
            "appconfiguration-template-fields",
            "Endpoint=${ENDPOINT};Id=${ID};Secret=${SECRET}",
            "azure-app-configuration",
            APP_RULE,
        ),
        (
            "mongodb-percent-template",
            "mongodb://synthetic:%3Cpassword%3E@db.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-percent-variable",
            "mongodb://synthetic:%24%7BPASSWORD%7D@db.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "servicebus-repeated-placeholder",
            service_placeholder.as_str(),
            "azure-servicebus",
            SERVICE_RULE,
        ),
        (
            "appconfiguration-repeated-placeholder",
            app_placeholder.as_str(),
            "azure-app-configuration",
            APP_RULE,
        ),
        (
            "mongodb-empty-password",
            "mongodb://synthetic:@db.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-empty-user",
            "mongodb://:synthetic@db.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-no-credentials",
            "mongodb://db.example.invalid/app",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-placeholder",
            "mongodb+srv://<username>:<password>@cluster.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-template",
            "mongodb://${USER}:${PASSWORD}@db.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-unescaped-reserved",
            "mongodb://synthetic:part:part@db.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-invalid-percent",
            "mongodb://synthetic:part%Q0part@db.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-invalid-srv-port",
            "mongodb+srv://synthetic:placeholder@db.example.invalid:27017/",
            "mongodb-uri",
            MONGO_RULE,
        ),
        (
            "mongodb-invalid-srv-host-list",
            "mongodb+srv://synthetic:placeholder@one.example.invalid,two.example.invalid/",
            "mongodb-uri",
            MONGO_RULE,
        ),
    ] {
        let mut value = case(
            id,
            "holdout",
            "native-reviewed-benign",
            text.as_bytes().to_vec(),
            &[rule, "generic-api-key"],
        );
        value.leakage_group = family.into();
        value.rationale = "Synthetic template or malformed near miss with no intended credential. The whole input is reviewed negative; malformed shape alone does not imply all real credentials are harmless.".into();
        cases.push(value);
    }
    // Fingerprints cover the input even when a future case builder mutates it.
    for value in cases {
        value.content_fnv1a64 = fingerprint(&value.input);
    }
}

fn gaps(cases: &mut Vec<Case>) {
    for (id, text, secret, family, rule) in [
        (
            "servicebus-sovereign-gap",
            format!(
                "Endpoint=sb://synthetic.servicebus.usgovcloudapi.net/;SharedAccessKeyName=synthetic;SharedAccessKey={SERVICE_KEY}"
            ),
            SERVICE_KEY,
            "azure-servicebus",
            SERVICE_RULE,
        ),
        (
            "appconfiguration-sovereign-gap",
            format!("Endpoint=https://synthetic.azconfig.azure.cn;Id=synthetic;Secret={APP_KEY}"),
            APP_KEY,
            "azure-app-configuration",
            APP_RULE,
        ),
        (
            "mongodb-ipv6-gap",
            format!("mongodb://synthetic:{MONGO_PASSWORD}@[::1]:27017/"),
            MONGO_PASSWORD,
            "mongodb-uri",
            MONGO_RULE,
        ),
    ] {
        let mut value = positive(id, text.into_bytes(), secret.as_bytes(), family, rule);
        value.stratum = "native-pilot-gap".into();
        value.rationale = "Synthetic credential-bearing form deliberately outside the bounded pilot grammar. Retained positive labels expose the gap; no native coverage or clean-scan claim is made.".into();
        cases.push(value);
    }
}
