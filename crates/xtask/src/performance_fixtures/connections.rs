//! Structural connection-string candidates await an explicit rule contract.

use super::{Fixture, Plant, json, seeded_value};

const FORMS: &[&str] = &[
    "uri-userinfo",
    "jdbc-query",
    "odbc-properties",
    "libpq-keyword",
];
const CLASSES: &[&str] = &[
    "literal",
    "percent-encoded",
    "empty",
    "omitted",
    "environment-placeholder",
    "template-placeholder",
    "public-url",
    "prose",
    "malformed-delimiter",
];

fn parts(form: &str) -> (&'static [u8], &'static [u8]) {
    match form {
        "uri-userinfo" => (b"postgresql://bench:", b"@db.invalid:5432/application"),
        "jdbc-query" => (
            b"jdbc:postgresql://db.invalid/application?user=bench&password=",
            b"&sslmode=require",
        ),
        "odbc-properties" => (
            b"Driver={Synthetic};Server=db.invalid;UID=bench;PWD=",
            b";Database=application;",
        ),
        "libpq-keyword" => (
            b"host=db.invalid user=bench password='",
            b"' dbname=application",
        ),
        _ => unreachable!("declared connection form"),
    }
}

fn apply_control_input(input: &mut Vec<u8>, form: &str, class: &str, password: &[u8]) {
    match class {
        "omitted" => {
            *input = match form {
                "uri-userinfo" => b"postgresql://bench@db.invalid/application".to_vec(),
                "jdbc-query" => b"jdbc:postgresql://db.invalid/application?user=bench".to_vec(),
                "odbc-properties" => b"Driver={Synthetic};Server=db.invalid;UID=bench;".to_vec(),
                "libpq-keyword" => b"host=db.invalid user=bench dbname=application".to_vec(),
                _ => unreachable!("declared connection form"),
            };
        }
        "public-url" => *input = b"https://public.invalid/documentation?language=en".to_vec(),
        "prose" => {
            *input = b"The database password is supplied by the application at startup.".to_vec();
        }
        "malformed-delimiter" => {
            *input = match form {
                "uri-userinfo" => [
                    b"postgresql://bench;".as_slice(),
                    password,
                    b"@db.invalid/application",
                ]
                .concat(),
                "jdbc-query" => [
                    b"jdbc:postgresql://db.invalid/application?user=bench&password:".as_slice(),
                    password,
                ]
                .concat(),
                "odbc-properties" => [
                    b"Server=db.invalid;UID=bench;PWD:".as_slice(),
                    password,
                    b";",
                ]
                .concat(),
                "libpq-keyword" => [
                    b"host=db.invalid user=bench password:'".as_slice(),
                    password,
                    b"'",
                ]
                .concat(),
                _ => unreachable!("declared connection form"),
            };
        }
        _ => {}
    }
}

pub(super) fn connection(form: &str, class: &str, ordinal: usize) -> Fixture {
    let password = seeded_value("connection-password", ordinal, 24);
    let (prefix, suffix) = parts(form);
    let mut value = password.clone();
    match class {
        "empty" => value.clear(),
        "environment-placeholder" => value = b"${PASSWORD}".to_vec(),
        "template-placeholder" => value = b"{{PASSWORD}}".to_vec(),
        "percent-encoded" => {
            value = format!("%{:02X}", password[0]).into_bytes();
            value.extend_from_slice(&password[1..]);
        }
        _ => {}
    }
    let mut input = prefix.to_vec();
    let start = input.len();
    input.extend_from_slice(&value);
    let end = input.len();
    input.extend_from_slice(suffix);
    apply_control_input(&mut input, form, class, &password);
    let carrier_end = input.len();
    input.push(b'\n');
    let mut fixture = Fixture::plain(
        format!("connection-{form}-{class}"),
        "connection-string-forms",
        input,
    );
    fixture.pat_contract = false;
    if matches!(class, "literal" | "percent-encoded") {
        fixture.plants.push(Plant {
            value,
            span: start..end,
            carrier: 0..carrier_end,
        });
    }
    let source_password = fixture.plants.first().map(|plant| plant.value.as_slice());
    let uri_percent = class == "percent-encoded" && matches!(form, "uri-userinfo" | "jdbc-query");
    let value_syntax = source_password.map(|_| {
        if class == "literal" {
            "literal"
        } else if uri_percent {
            "uri-percent-encoded"
        } else {
            "literal-percent-containing"
        }
    });
    let retained_literal = if class == "malformed-delimiter" {
        let start = match form {
            "uri-userinfo" => b"postgresql://bench;".len(),
            "jdbc-query" => b"jdbc:postgresql://db.invalid/application?user=bench&password:".len(),
            "odbc-properties" => b"Server=db.invalid;UID=bench;PWD:".len(),
            "libpq-keyword" => b"host=db.invalid user=bench password:'".len(),
            _ => unreachable!("declared connection form"),
        };
        Some(json!({
            "source_bytes": {"start": start, "end": start + password.len()},
            "value_sha256": super::sha256_bytes(&password),
            "role": "generated-literal-outside-declared-password-slot",
        }))
    } else {
        None
    };
    fixture.details = json!({
        "form": form,
        "class": class,
        "generated_password_bytes": password.len(),
        "generated_password_sha256": super::sha256_bytes(&password),
        "value_syntax": value_syntax,
        "wire_value_differs_from_semantic_password": source_password.map(|_| uri_percent),
        "source_password_sha256": source_password.map(super::sha256_bytes),
        "semantic_password_sha256": source_password.map(|value| super::sha256_bytes(if uri_percent { password.as_slice() } else { value })),
        "retained_literal": retained_literal,
        "proposed_classification": if matches!(class, "literal" | "percent-encoded") { "candidate-positive" } else { "candidate-negative" },
        "required_review": "rule-owner-must-approve-syntax-capture-placeholder-and-decoding-semantics-before-assigning-pass-expectations",
        "profile": "explicit-reviewed-expanded-rules; native-catalog-coverage-separate",
        "scope_limit": "source-spelling-is-the-comparison-value; semantic-hashes-never-replace-raw-captures",
    });
    fixture
}

pub(super) fn generate(emit: &mut impl FnMut(Fixture) -> Result<(), String>) -> Result<(), String> {
    for (form_index, form) in FORMS.iter().enumerate() {
        for (class_index, class) in CLASSES.iter().enumerate() {
            emit(connection(
                form,
                class,
                form_index * CLASSES.len() + class_index,
            ))?;
        }
    }
    Ok(())
}
