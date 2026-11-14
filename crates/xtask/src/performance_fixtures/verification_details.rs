//! Admission checks written against the fixed recipe, not generator helpers.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::sha256_bytes;
use super::verification::{field, number, range, require_fields};
use super::verification_domain::Spec;
use super::verification_seed;

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn plants(manifest: &Value) -> Result<&[Value], String> {
    manifest["plants"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| "missing plants".into())
}

fn token(bytes: &[u8], class: &str) -> bool {
    if bytes.len() != 40 {
        return false;
    }
    match class {
        "positive" => {
            bytes.starts_with(b"ghp_") && bytes[4..].iter().all(u8::is_ascii_alphanumeric)
        }
        "prefix-negative" => {
            bytes.starts_with(b"zhp_") && bytes[4..].iter().all(u8::is_ascii_alphanumeric)
        }
        "internal-negative" => {
            bytes.starts_with(b"ghp_")
                && bytes[22] == b'_'
                && bytes[4..22]
                    .iter()
                    .chain(&bytes[23..])
                    .all(u8::is_ascii_alphanumeric)
        }
        _ => false,
    }
}

pub(super) fn verify(
    spec: Spec,
    input: &[u8],
    plaintext: &[u8],
    manifest: &Value,
) -> Result<(), String> {
    let names: &[&str] = match spec {
        Spec::Boundary { .. } | Spec::Partition { .. } => &[
            "anchor_byte",
            "split_offset_in_carrier",
            "carrier_bytes",
            "carrier_length",
            "padding_split_probe",
            "layout",
            "class",
            "source_modes",
            "anchor_semantics",
            "negative_contract",
        ],
        Spec::Density { .. } => &[
            "records",
            "record_bytes",
            "class",
            "identity_pattern",
            "separator",
            "literal_line_payload_upper_bound_bytes",
            "single_line_timing_cap_input_bytes",
            "untimed_reason",
            "pair_contract",
        ],
        Spec::Decoded { .. } => &[
            "inner_records",
            "identity_pattern",
            "class",
            "shared_outer_span",
            "required_multiplicity",
            "literal_line_payload_upper_bound_bytes",
            "timed_inner_record_cap",
            "untimed_reason",
            "encoding_policy",
        ],
        Spec::Connection { .. } => &[
            "form",
            "class",
            "generated_password_bytes",
            "generated_password_sha256",
            "value_syntax",
            "wire_value_differs_from_semantic_password",
            "source_password_sha256",
            "semantic_password_sha256",
            "retained_literal",
            "proposed_classification",
            "required_review",
            "profile",
            "scope_limit",
        ],
    };
    require_fields(&manifest["details"], names)?;
    match spec {
        Spec::Boundary {
            anchor,
            split,
            encoded,
            class,
            layout,
        } => boundary(
            input, plaintext, manifest, anchor, split, encoded, class, layout,
        ),
        Spec::Density {
            bytes,
            class,
            identity,
            separator,
        } => density(input, manifest, bytes, class, identity, separator),
        Spec::Decoded {
            count,
            depth,
            identity,
            positive,
        } => decoded(input, plaintext, manifest, count, depth, identity, positive),
        Spec::Connection { form, class } => connection(input, manifest, form, class),
        Spec::Partition { encoded } => {
            boundary(
                input,
                plaintext,
                manifest,
                4096,
                if encoded { 55 } else { 20 },
                encoded,
                "positive",
                "no-lf",
            )?;
            schedules(input.len(), &manifest["details"])
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "independent boundary specification dimensions"
)]
fn boundary(
    input: &[u8],
    plaintext: &[u8],
    manifest: &Value,
    anchor: usize,
    split: usize,
    encoded: bool,
    class: &str,
    layout: &str,
) -> Result<(), String> {
    let details = &manifest["details"];
    let length = if encoded { 56 } else { 40 };
    let start = anchor - split;
    let end = start + length;
    require(input.len() == end + 64, "boundary input length differs")?;
    require(
        number(&details["anchor_byte"])? == anchor
            && number(&details["split_offset_in_carrier"])? == split
            && number(&details["carrier_length"])? == length
            && range(&details["carrier_bytes"], input.len())? == (start..end)
            && details["padding_split_probe"] == (encoded && matches!(split, 54 | 55))
            && details["class"] == class
            && details["layout"] == layout
            && details["source_modes"] == json!(["file", "stdin"])
            && details["anchor_semantics"]
                == "prescribed-byte-anchor; actual-reader-fragment-boundaries-are-observations"
            && details["negative_contract"]
                == "mutated-prefix-or-internal-forbidden-separator; no-length-only-negatives"
            && number(&manifest["decode_depth"])? == usize::from(encoded)
            && manifest["timing_eligible_after_scope_and_quality_gate"] == false,
        "boundary geometry, class, source modes, or timing metadata differs",
    )?;
    let value = if encoded {
        require(
            range(
                &manifest["physical_source_encoded_carrier_bytes"],
                input.len(),
            )? == (start..end),
            "boundary outer carrier differs",
        )?;
        require(&input[end - 2..end] == b"==", "boundary padding differs")?;
        plaintext
    } else {
        &input[start..end]
    };
    require(
        token(value, class),
        "boundary token does not satisfy its declared class",
    )?;
    require(
        value == verification_seed::pat("boundary", anchor * 100 + split, class),
        "boundary token differs from the declared seed recipe",
    )?;
    require(
        plants(manifest)?.len() == usize::from(class == "positive"),
        "boundary literal event count differs",
    )?;
    for (index, byte) in input.iter().enumerate() {
        if (start..end).contains(&index) {
            continue;
        }
        let expected = match layout {
            "no-lf" => b' ',
            "lf" => {
                if index == start - 1 || index == end || index % 64 == 63 {
                    b'\n'
                } else {
                    b' '
                }
            }
            "crlf" => {
                if index == start - 2 || index == end {
                    b'\r'
                } else if index == start - 1 || index == end + 1 {
                    b'\n'
                } else {
                    match index % 64 {
                        62 => b'\r',
                        63 => b'\n',
                        _ => b' ',
                    }
                }
            }
            "invalid-bytes" => {
                if index == start - 1 {
                    0xff
                } else if index == end {
                    0xfe
                } else {
                    b' '
                }
            }
            _ => return Err("unknown boundary layout".into()),
        };
        require(
            *byte == expected,
            "boundary neighbor or filler layout differs",
        )?;
    }
    Ok(())
}

fn identity(values: &[&[u8]], pattern: &str) -> Result<(), String> {
    let distinct = values.iter().copied().collect::<BTreeSet<_>>().len();
    require(
        distinct
            == if pattern == "repeated" {
                1
            } else {
                values.len()
            },
        "record identity pattern differs",
    )
}

fn density(
    input: &[u8],
    manifest: &Value,
    bytes: usize,
    class: &str,
    pattern: &str,
    separator: &str,
) -> Result<(), String> {
    let records = bytes / 64;
    let lf = separator == "lf";
    let expected_count = match class {
        "positive" => records,
        "alternating" => records / 2,
        "negative" => 0,
        _ => return Err("unknown density class".into()),
    };
    let timing = lf || bytes == 32768;
    let details = &manifest["details"];
    require(
        input.len() == bytes && number(&manifest["decode_depth"])? == 0,
        "density input length or encoding differs",
    )?;
    require(
        number(&details["records"])? == records
            && number(&details["record_bytes"])? == 64
            && details["class"] == class
            && details["identity_pattern"] == pattern
            && details["separator"] == if lf { "LF" } else { "space" }
            && details["pair_contract"]
                == "changing-LF-to-space-only-changes-record-final-byte; repeated-and-unique-pairs-preserve-positive-offsets"
            && number(&details["literal_line_payload_upper_bound_bytes"])?
                == expected_count * if lf { 65 } else { bytes }
            && number(&details["single_line_timing_cap_input_bytes"])? == 32768
            && manifest["timing_eligible_after_scope_and_quality_gate"] == timing
            && field(details, "untimed_reason")?
                == &if timing {
                    Value::Null
                } else {
                    json!(
                        "predeclared-single-line-report-growth-cap; retain-as-unmeasured-quality-input"
                    )
                }
            && plants(manifest)?.len() == expected_count,
        "density geometry, count, identity, or timing metadata differs",
    )?;
    let mut values = Vec::with_capacity(records);
    for (ordinal, record) in input.chunks_exact(64).enumerate() {
        let accepted = class == "positive" || class == "alternating" && ordinal % 2 == 0;
        require(
            &record[..10] == b"{\"value\":\""
                && &record[50..52] == b"\"}"
                && record[52..63].iter().all(|byte| *byte == b' ')
                && record[63] == if lf { b'\n' } else { b' ' },
            "density record wrapper differs",
        )?;
        let value = &record[10..50];
        require(
            token(
                value,
                if accepted {
                    "positive"
                } else {
                    "internal-negative"
                },
            ),
            "density record class differs",
        )?;
        require(
            value
                == verification_seed::pat(
                    "density",
                    if pattern == "repeated" { 0 } else { ordinal },
                    if accepted {
                        "positive"
                    } else {
                        "internal-negative"
                    },
                ),
            "density token differs from its declared seed and pair identity",
        )?;
        values.push(value);
    }
    // Alternating records intentionally differ by their inserted separator.
    // Compare their underlying identity after undoing exactly that mutation.
    if pattern == "repeated" && class == "alternating" {
        let first = values[0];
        require(
            values
                .iter()
                .all(|value| value[..22] == first[..22] && value[23..] == first[23..]),
            "alternating repeated identities differ",
        )
    } else {
        identity(&values, pattern)
    }
}

fn decoded(
    input: &[u8],
    plaintext: &[u8],
    manifest: &Value,
    count: usize,
    depth: usize,
    pattern: &str,
    positive: bool,
) -> Result<(), String> {
    let details = &manifest["details"];
    let expected_count = if positive { count } else { 0 };
    let timing = count <= 256;
    require(
        plaintext.len() == count * 53
            && input.starts_with(b"{\"encoded\":\"")
            && input.ends_with(b"\"}\n"),
        "decoded record or carrier shape differs",
    )?;
    require(
        range(
            &manifest["physical_source_encoded_carrier_bytes"],
            input.len(),
        )? == (12..input.len() - 3)
            && number(&manifest["decode_depth"])? == depth
            && number(&details["inner_records"])? == count
            && details["identity_pattern"] == pattern
            && details["class"]
                == if positive {
                    "positive"
                } else {
                    "internal-separator-negative"
                }
            && details["shared_outer_span"] == true
            && details["required_multiplicity"]
                == "preserve-every-plaintext-occurrence-even-when-value-and-outer-span-repeat"
            && details["encoding_policy"]
                == "standard-padded-base64; URL-safe-unpadded-invalid-padding-not-assumed-equivalent"
            && number(&details["literal_line_payload_upper_bound_bytes"])?
                == expected_count * input.len()
            && number(&details["timed_inner_record_cap"])? == 256
            && manifest["timing_eligible_after_scope_and_quality_gate"] == timing
            && field(details, "untimed_reason")?
                == &if timing {
                    Value::Null
                } else {
                    json!("predeclared-shared-outer-line-report-growth-cap")
                }
            && plants(manifest)?.len() == expected_count,
        "decoded count, identity, carrier, or timing metadata differs",
    )?;
    let mut values = Vec::with_capacity(count);
    for (ordinal, record) in plaintext.chunks_exact(53).enumerate() {
        require(
            record.starts_with(b"{\"value\":\"") && record.ends_with(b"\"}\n"),
            "decoded plaintext wrapper differs",
        )?;
        let value = &record[10..50];
        require(
            token(
                value,
                if positive {
                    "positive"
                } else {
                    "internal-negative"
                },
            ),
            "decoded plaintext class differs",
        )?;
        require(
            value
                == verification_seed::pat(
                    "single-carrier",
                    if pattern == "repeated" { 0 } else { ordinal },
                    if positive {
                        "positive"
                    } else {
                        "internal-negative"
                    },
                ),
            "decoded token differs from its declared seed recipe",
        )?;
        values.push(value);
    }
    identity(&values, pattern)
}

fn schedules(length: usize, details: &Value) -> Result<(), String> {
    require_fields(
        details,
        &["reader_schedules", "error_schedules", "read_contract"],
    )?;
    require(
        details["read_contract"]
            == "Rust Read returns bytes or error per call; error-after-bytes means a subsequent call. Interrupted retries require a separate adapter test. A zero read is EOF, not an invented retryable no-progress signal.",
        "reader API contract differs",
    )?;
    let schedules = details["reader_schedules"]
        .as_array()
        .ok_or("missing reader schedules")?;
    let required: &[&[usize]] = &[&[1], &[2], &[7], &[4096], &[1, 3, 2, 7, 31, 64, 5]];
    require(
        schedules.len() == required.len(),
        "reader schedule count differs",
    )?;
    for (schedule, sizes) in schedules.iter().zip(required) {
        require(
            schedule["cyclic_successful_read_sizes"] == json!(sizes)
                && schedule["terminal_read"] == "zero-after-all-input-bytes"
                && schedule["expected_status"] == "complete-with-exact-planted-occurrences",
            "reader sizes, EOF, or status differs",
        )?;
        let partitions = schedule["partitions"]
            .as_array()
            .ok_or("missing read partitions")?;
        let mut cursor = 0;
        for (ordinal, part) in partitions.iter().enumerate() {
            require(
                cursor < length,
                "reader schedule contains an extra read partition",
            )?;
            let next = length.min(cursor + sizes[ordinal % sizes.len()]);
            require(
                range(part, length)? == (cursor..next),
                "read partition violates cyclic size or contiguous coverage",
            )?;
            cursor = next;
        }
        require(cursor == length, "read partitions omit source bytes")?;
    }
    let errors = details["error_schedules"]
        .as_array()
        .ok_or("missing error schedules")?;
    require(errors.len() == 3, "error schedule count differs")?;
    for (error, (offset, terminal)) in errors.iter().zip([
        (0, "io-error"),
        (4096, "io-error"),
        (length, "io-error-instead-of-clean-eof"),
    ]) {
        require(
            number(&error["successful_bytes_before_error"])? == offset
                && error["terminal_read"] == terminal
                && error["expected_status"] == "incomplete",
            "error schedule offset, terminal error, or incomplete status differs",
        )?;
    }
    Ok(())
}

fn connection_parts(form: &str) -> (&'static [u8], &'static [u8]) {
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
        _ => unreachable!("independent matrix has declared connection forms"),
    }
}

fn connection(input: &[u8], manifest: &Value, form: &str, class: &str) -> Result<(), String> {
    let details = &manifest["details"];
    let seeded_password = verification_seed::connection_password(form, class)?;
    let proposed_positive = matches!(class, "literal" | "percent-encoded");
    let uri_percent = class == "percent-encoded" && matches!(form, "uri-userinfo" | "jdbc-query");
    let source_value = if class == "percent-encoded" {
        let mut value = format!("%{:02X}", seeded_password[0]).into_bytes();
        value.extend_from_slice(&seeded_password[1..]);
        value
    } else {
        seeded_password.clone()
    };
    let syntax = proposed_positive.then_some(if class == "literal" {
        "literal"
    } else if uri_percent {
        "uri-percent-encoded"
    } else {
        "literal-percent-containing"
    });
    let semantic_value = if uri_percent {
        seeded_password.as_slice()
    } else {
        source_value.as_slice()
    };
    require(
        input.ends_with(b"\n")
            && number(&manifest["decode_depth"])? == 0
            && details["form"] == form
            && details["class"] == class
            && number(&details["generated_password_bytes"])? == 24
            && details["generated_password_sha256"] == sha256_bytes(&seeded_password)
            && details.get("password_sha256").is_none()
            && details.get("literal_password_bytes").is_none()
            && details["value_syntax"] == json!(syntax)
            && details["source_password_sha256"]
                == json!(proposed_positive.then(|| sha256_bytes(&source_value)))
            && details["semantic_password_sha256"]
                == json!(proposed_positive.then(|| sha256_bytes(semantic_value)))
            && details["required_review"]
                == "rule-owner-must-approve-syntax-capture-placeholder-and-decoding-semantics-before-assigning-pass-expectations"
            && details["profile"]
                == "explicit-reviewed-expanded-rules; native-catalog-coverage-separate"
            && details["scope_limit"]
                == "source-spelling-is-the-comparison-value; semantic-hashes-never-replace-raw-captures"
            && details["wire_value_differs_from_semantic_password"]
                == json!(proposed_positive.then_some(uri_percent))
            && details["proposed_classification"]
                == if proposed_positive {
                    "candidate-positive"
                } else {
                    "candidate-negative"
                }
            && manifest["timing_eligible_after_scope_and_quality_gate"] == false
            && plants(manifest)?.len() == usize::from(proposed_positive),
        "connection construction metadata differs",
    )?;
    if class != "malformed-delimiter" {
        require(
            details["retained_literal"].is_null(),
            "unexpected retained non-password literal",
        )?;
    }
    connection_carrier(
        input,
        manifest,
        form,
        class,
        &seeded_password,
        &source_value,
    )
}

fn connection_carrier(
    input: &[u8],
    manifest: &Value,
    form: &str,
    class: &str,
    seeded_password: &[u8],
    source_value: &[u8],
) -> Result<(), String> {
    let details = &manifest["details"];
    let proposed_positive = matches!(class, "literal" | "percent-encoded");
    let uri_percent = class == "percent-encoded" && matches!(form, "uri-userinfo" | "jdbc-query");
    let semantic_value = if uri_percent {
        seeded_password
    } else {
        source_value
    };
    let carrier = &input[..input.len() - 1];
    let (prefix, suffix) = connection_parts(form);
    match class {
        "literal"
        | "percent-encoded"
        | "empty"
        | "environment-placeholder"
        | "template-placeholder" => {
            require(
                carrier.starts_with(prefix)
                    && carrier.ends_with(suffix)
                    && carrier.len() >= prefix.len() + suffix.len(),
                "connection carrier delimiters differ",
            )?;
            let value = &carrier[prefix.len()..carrier.len() - suffix.len()];
            if proposed_positive {
                let plant = &plants(manifest)?[0];
                require(
                    range(&plant["plaintext_secret_bytes"], input.len())?
                        == (prefix.len()..carrier.len() - suffix.len())
                        && range(&plant["plaintext_carrier_bytes"], input.len())?
                            == (0..carrier.len()),
                    "connection literal span differs",
                )?;
                require(
                    value == source_value,
                    "connection source spelling differs from its recipe",
                )?;
                // ODBC and libpq percent bytes are literal password data.
                let semantic = if uri_percent {
                    require(
                        value.len() == 26 && value[0] == b'%',
                        "percent-encoded literal shape differs",
                    )?;
                    let hex =
                        std::str::from_utf8(&value[1..3]).map_err(|_| "invalid percent escape")?;
                    let first =
                        u8::from_str_radix(hex, 16).map_err(|_| "invalid percent escape")?;
                    [vec![first], value[3..].to_vec()].concat()
                } else {
                    value.to_vec()
                };
                require(
                    semantic.as_slice() == semantic_value
                        && details["source_password_sha256"] == sha256_bytes(value)
                        && details["semantic_password_sha256"] == sha256_bytes(&semantic),
                    "literal connection password identity differs",
                )?;
            } else {
                let expected: &[u8] = match class {
                    "empty" => b"",
                    "environment-placeholder" => b"${PASSWORD}",
                    _ => b"{{PASSWORD}}",
                };
                require(
                    value == expected,
                    "connection placeholder or empty control differs",
                )?;
            }
        }
        "omitted" => {
            let expected: &[u8] = match form {
                "uri-userinfo" => b"postgresql://bench@db.invalid/application",
                "jdbc-query" => b"jdbc:postgresql://db.invalid/application?user=bench",
                "odbc-properties" => b"Driver={Synthetic};Server=db.invalid;UID=bench;",
                _ => b"host=db.invalid user=bench dbname=application",
            };
            require(carrier == expected, "omitted-password control differs")?;
        }
        "public-url" => require(
            carrier == b"https://public.invalid/documentation?language=en",
            "public URL control differs",
        )?,
        "prose" => require(
            carrier == b"The database password is supplied by the application at startup.",
            "prose control differs",
        )?,
        "malformed-delimiter" => {
            malformed_connection(carrier, details, form, seeded_password)?;
        }
        _ => return Err("unknown connection control".into()),
    }
    Ok(())
}

fn malformed_connection(
    carrier: &[u8],
    details: &Value,
    form: &str,
    seeded_password: &[u8],
) -> Result<(), String> {
    let (prefix, suffix): (&[u8], &[u8]) = match form {
        "uri-userinfo" => (b"postgresql://bench;", b"@db.invalid/application"),
        "jdbc-query" => (
            b"jdbc:postgresql://db.invalid/application?user=bench&password:",
            b"",
        ),
        "odbc-properties" => (b"Server=db.invalid;UID=bench;PWD:", b";"),
        _ => (b"host=db.invalid user=bench password:'", b"'"),
    };
    require(
        carrier.len() == prefix.len() + 24 + suffix.len()
            && carrier.starts_with(prefix)
            && carrier.ends_with(suffix),
        "malformed-delimiter carrier differs",
    )?;
    let password = &carrier[prefix.len()..prefix.len() + 24];
    require(
        password.iter().all(u8::is_ascii_alphanumeric)
            && password == seeded_password
            && details["generated_password_sha256"] == sha256_bytes(password),
        "malformed-delimiter literal differs",
    )?;
    require(
        details["retained_literal"]
            == json!({
                "source_bytes": {"start": prefix.len(), "end": prefix.len() + 24},
                "value_sha256": sha256_bytes(password),
                "role": "generated-literal-outside-declared-password-slot",
            }),
        "malformed literal must remain separate from a structural password slot",
    )?;
    Ok(())
}
