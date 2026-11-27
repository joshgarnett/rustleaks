//! Checks that `include/rustleaks.h` declares exactly the exported
//! functions with matching parameter types, the same constant values, and
//! struct fields whose C layout equals the Rust layout.

use std::collections::BTreeMap;
use std::mem::{offset_of, size_of};

use crate::abi::{self, Bytes, FindingView, RuleView, ScanArgs, StatusView};

const HEADER: &str = include_str!("../include/rustleaks.h");
const EXPORTS: &str = include_str!("exports.rs");
const ABI: &str = include_str!("abi.rs");

/// Removes `/* ... */` comments.
fn strip_comments(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        let end = rest[start..].find("*/").expect("closed comment") + start + 2;
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn normalize(text: &str) -> String {
    text.replace('*', " * ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Header function name to normalized parameter types.
fn header_functions(header: &str) -> BTreeMap<String, Vec<String>> {
    let mut functions = BTreeMap::new();
    for declaration in header.split(';') {
        let declaration = declaration.trim();
        let Some(rest) = declaration.strip_prefix("int32_t rustleaks_") else {
            continue;
        };
        let open = rest.find('(').expect("parameter list");
        let name = format!("rustleaks_{}", &rest[..open]);
        let parameters = rest[open + 1..rest.rfind(')').expect("closed list")]
            .split(',')
            .map(|parameter| {
                let parameter = normalize(parameter);
                // Drop the parameter name, the last word.
                let words = parameter.split(' ').collect::<Vec<_>>();
                words[..words.len() - 1].join(" ")
            })
            .collect();
        assert!(
            functions.insert(name.clone(), parameters).is_none(),
            "{name} is declared twice"
        );
    }
    functions
}

/// The C spelling of a Rust parameter type.
fn c_type(rust: &str) -> String {
    // `stringify!` can put a space after the `*` of a pointer type.
    let spelled = rust
        .replace("* const ", "*const ")
        .replace("* mut ", "*mut ");
    let mut rust = spelled.trim();
    let mut pointers = Vec::new();
    loop {
        if let Some(rest) = rust.strip_prefix("*const ") {
            pointers.push(true);
            rust = rest;
        } else if let Some(rest) = rust.strip_prefix("*mut ") {
            pointers.push(false);
            rust = rest;
        } else {
            break;
        }
    }
    let base = match rust {
        "u8" => "uint8_t",
        "f64" => "double",
        "Bytes" => "rustleaks_bytes",
        "u32" => "uint32_t",
        "u64" => "uint64_t",
        "i32" => "int32_t",
        "usize" => "size_t",
        "Options" => "rustleaks_options",
        "EngineHandle" => "rustleaks_engine",
        "CancelHandle" => "rustleaks_cancel",
        "ResultHandle" => "rustleaks_result",
        "FfiError" => "rustleaks_error",
        "ScanArgs" => "rustleaks_scan_args",
        "RuleView" => "rustleaks_rule_view",
        "FindingView" => "rustleaks_finding_view",
        "StatusView" => "rustleaks_status_view",
        other => panic!("no C type for Rust type {other}"),
    };
    // The innermost pointer's constness applies to the base type.
    let mut c = String::new();
    if pointers.last() == Some(&true) {
        c.push_str("const ");
    }
    c.push_str(base);
    for (index, constant) in pointers.iter().enumerate().rev() {
        c.push_str(" *");
        // A const pointer to a pointer would need `* const`, which the ABI
        // does not use.
        assert!(
            index == pointers.len() - 1 || !constant,
            "unexpected const pointer to pointer in {rust}"
        );
    }
    normalize(&c)
}

/// Exported function name to C parameter types, from the Rust source.
fn rust_functions(source: &str) -> BTreeMap<String, Vec<String>> {
    let mut functions = BTreeMap::new();
    for item in source.split("pub unsafe extern \"C\" fn ").skip(1) {
        let open = item.find('(').expect("parameter list");
        let name = item[..open].to_owned();
        let close = item.find(") -> i32").expect("returns a status");
        let parameters = item[open + 1..close]
            .split(',')
            .map(str::trim)
            .filter(|parameter| !parameter.is_empty())
            .map(|parameter| {
                let (_, rust) = parameter.split_once(':').expect("typed parameter");
                c_type(rust)
            })
            .collect();
        assert!(functions.insert(name, parameters).is_none());
    }
    functions
}

#[test]
fn header_declares_every_export_with_its_parameter_types() {
    let header = header_functions(&strip_comments(HEADER));
    let exports = rust_functions(EXPORTS);
    assert_eq!(exports.len(), 25, "{:?}", exports.keys());
    assert_eq!(header, exports);
    for name in exports.keys() {
        assert_eq!(
            EXPORTS.matches(&format!("fn {name}(")).count(),
            1,
            "{name} is exported once"
        );
    }
    let no_mangle = EXPORTS
        .matches("#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn")
        .count();
    assert_eq!(no_mangle, exports.len(), "every export is unmangled");
}

fn header_defines(header: &str) -> BTreeMap<String, u64> {
    strip_comments(header)
        .lines()
        .filter_map(|line| line.trim().strip_prefix("#define RUSTLEAKS_"))
        .filter_map(|rest| {
            let mut words = rest.split_whitespace();
            let name = words.next()?;
            let value = words.next()?;
            let value = if value == "UINT64_MAX" {
                u64::MAX
            } else {
                value.parse().expect("decimal value")
            };
            Some((format!("RUSTLEAKS_{name}"), value))
        })
        .collect()
}

#[allow(
    clippy::cast_sign_loss,
    reason = "every status and code is not negative"
)]
fn rust_constants() -> BTreeMap<String, u64> {
    let values: &[(&str, u64)] = &[
        ("ABI_VERSION", u64::from(abi::ABI_VERSION)),
        ("OK", abi::STATUS_OK as u64),
        ("ERROR_INVALID_ARGUMENT", abi::ERROR_INVALID_ARGUMENT as u64),
        ("ERROR_ABI_MISMATCH", abi::ERROR_ABI_MISMATCH as u64),
        ("ERROR_CONFIG", abi::ERROR_CONFIG as u64),
        ("ERROR_RULE_SELECTION", abi::ERROR_RULE_SELECTION as u64),
        ("ERROR_ENGINE", abi::ERROR_ENGINE as u64),
        ("ERROR_INPUT_TOO_LARGE", abi::ERROR_INPUT_TOO_LARGE as u64),
        ("ERROR_CLOSED", abi::ERROR_CLOSED as u64),
        ("ERROR_PANIC", abi::ERROR_PANIC as u64),
        ("UNLIMITED", abi::UNLIMITED),
        ("OPTION_DECODE_DEPTH", u64::from(abi::OPTION_DECODE_DEPTH)),
        ("OPTION_BASE64_MODE", u64::from(abi::OPTION_BASE64_MODE)),
        (
            "OPTION_REDACTION_PERCENT",
            u64::from(abi::OPTION_REDACTION_PERCENT),
        ),
        (
            "OPTION_MAX_INPUT_BYTES",
            u64::from(abi::OPTION_MAX_INPUT_BYTES),
        ),
        (
            "OPTION_MAX_DECODED_BYTES",
            u64::from(abi::OPTION_MAX_DECODED_BYTES),
        ),
        (
            "OPTION_MAX_WORK_UNITS",
            u64::from(abi::OPTION_MAX_WORK_UNITS),
        ),
        (
            "OPTION_MAX_FINDING_RECORDS",
            u64::from(abi::OPTION_MAX_FINDING_RECORDS),
        ),
        (
            "OPTION_MAX_FINDING_PAYLOAD_BYTES",
            u64::from(abi::OPTION_MAX_FINDING_PAYLOAD_BYTES),
        ),
        (
            "OPTION_MAX_COLLECTED_SPANS",
            u64::from(abi::OPTION_MAX_COLLECTED_SPANS),
        ),
        (
            "OPTION_MAX_NORMALIZATION_BYTES",
            u64::from(abi::OPTION_MAX_NORMALIZATION_BYTES),
        ),
        ("OPTION_WORKERS", u64::from(abi::OPTION_WORKERS)),
        ("MAX_WORKERS", abi::MAX_WORKERS),
        (
            "OPTION_ALLOW_COMMENTS",
            u64::from(abi::OPTION_ALLOW_COMMENTS),
        ),
        (
            "OPTION_SCAN_ON_CALLER_THREAD",
            u64::from(abi::OPTION_SCAN_ON_CALLER_THREAD),
        ),
        ("BASE64_COMPATIBLE", abi::BASE64_COMPATIBLE),
        ("BASE64_EXTENDED", abi::BASE64_EXTENDED),
        ("SCAN_SET_DECODE_DEPTH", abi::SCAN_SET_DECODE_DEPTH),
        ("SCAN_SET_BASE64_MODE", abi::SCAN_SET_BASE64_MODE),
        (
            "SCAN_SET_REDACTION_PERCENT",
            abi::SCAN_SET_REDACTION_PERCENT,
        ),
        ("SCAN_SET_ALLOW_COMMENTS", abi::SCAN_SET_ALLOW_COMMENTS),
        (
            "SCAN_SET_MAX_DECODED_BYTES",
            abi::SCAN_SET_MAX_DECODED_BYTES,
        ),
        ("SCAN_SET_MAX_WORK_UNITS", abi::SCAN_SET_MAX_WORK_UNITS),
        (
            "SCAN_SET_MAX_FINDING_RECORDS",
            abi::SCAN_SET_MAX_FINDING_RECORDS,
        ),
        (
            "SCAN_SET_MAX_FINDING_PAYLOAD_BYTES",
            abi::SCAN_SET_MAX_FINDING_PAYLOAD_BYTES,
        ),
        (
            "SCAN_SET_MAX_COLLECTED_SPANS",
            abi::SCAN_SET_MAX_COLLECTED_SPANS,
        ),
        (
            "SCAN_SET_MAX_NORMALIZATION_BYTES",
            abi::SCAN_SET_MAX_NORMALIZATION_BYTES,
        ),
        ("SCAN_SET_DEADLINE", abi::SCAN_SET_DEADLINE),
        ("SCAN_SET_ALL", abi::SCAN_SET_ALL),
        ("TERMINATION_COMPLETE", abi::TERMINATION_COMPLETE as u64),
        ("TERMINATION_CANCELLED", abi::TERMINATION_CANCELLED as u64),
        ("TERMINATION_DEADLINE", abi::TERMINATION_DEADLINE as u64),
        ("TERMINATION_BUDGET", abi::TERMINATION_BUDGET as u64),
        ("TERMINATION_OTHER", abi::TERMINATION_OTHER as u64),
        ("BUDGET_NONE", abi::BUDGET_NONE as u64),
        ("BUDGET_DECODED_BYTES", abi::BUDGET_DECODED_BYTES as u64),
        ("BUDGET_WORK_UNITS", abi::BUDGET_WORK_UNITS as u64),
        ("BUDGET_FINDING_RECORDS", abi::BUDGET_FINDING_RECORDS as u64),
        (
            "BUDGET_FINDING_PAYLOAD_BYTES",
            abi::BUDGET_FINDING_PAYLOAD_BYTES as u64,
        ),
        ("BUDGET_COLLECTED_SPANS", abi::BUDGET_COLLECTED_SPANS as u64),
        (
            "BUDGET_NORMALIZATION_BYTES",
            abi::BUDGET_NORMALIZATION_BYTES as u64,
        ),
    ];
    values
        .iter()
        .map(|(name, value)| (format!("RUSTLEAKS_{name}"), *value))
        .collect()
}

#[test]
fn header_defines_every_abi_constant_with_its_value() {
    let constants = rust_constants();
    assert_eq!(header_defines(HEADER), constants);
    // Every public constant in abi.rs is in the table above.
    let declared = ABI
        .lines()
        .filter_map(|line| line.strip_prefix("pub const "))
        .map(|rest| rest.split(':').next().expect("named constant"))
        .collect::<Vec<_>>();
    assert_eq!(declared.len(), constants.len());
    for name in declared {
        let header_name = if name == "STATUS_OK" {
            "RUSTLEAKS_OK".to_owned()
        } else {
            format!("RUSTLEAKS_{name}")
        };
        assert!(constants.contains_key(&header_name), "{name}");
    }
}

/// Size and alignment of a C field type on the supported 64-bit targets.
fn c_layout(field_type: &str) -> (usize, usize) {
    if field_type.ends_with('*') {
        return (8, 8);
    }
    match field_type {
        "uint8_t" => (1, 1),
        "int32_t" | "uint32_t" => (4, 4),
        "uint64_t" | "size_t" | "double" => (8, 8),
        "rustleaks_bytes" => (16, 8),
        other => panic!("unknown C field type {other}"),
    }
}

/// Fields with their names, offsets and C types, and the struct size.
type Layout = (Vec<(String, usize, String)>, usize);

/// Struct name to its fields with their C offsets and C types, and its C
/// size.
fn header_structs(header: &str) -> BTreeMap<String, Layout> {
    let mut structs = BTreeMap::new();
    for block in header.split("typedef struct ").skip(1) {
        let Some(open) = block.find('{') else {
            continue;
        };
        let name = block[..open].trim().to_owned();
        let close = block.find('}').expect("closed struct");
        let mut offset = 0_usize;
        let mut align = 1_usize;
        let mut fields = Vec::new();
        for line in block[open + 1..close].split(';') {
            let line = normalize(line);
            if line.is_empty() {
                continue;
            }
            let (field_type, field) = line.rsplit_once(' ').expect("typed field");
            let (size, field_align) = c_layout(field_type.trim_start_matches("const "));
            offset = offset.next_multiple_of(field_align);
            fields.push((field.to_owned(), offset, field_type.to_owned()));
            offset += size;
            align = align.max(field_align);
        }
        structs.insert(name, (fields, offset.next_multiple_of(align)));
    }
    structs
}

/// Each field's name, Rust offset and the C spelling of its Rust type, and
/// the Rust size. The closure fails to compile unless every listed type is
/// the field's real type.
macro_rules! rust_layout {
    ($type:ty, [$($field:ident: $field_type:ty),* $(,)?]) => {{
        $(let _: fn(&$type) -> &$field_type = |value| &value.$field;)*
        (
            vec![$((
                stringify!($field).to_owned(),
                offset_of!($type, $field),
                c_type(stringify!($field_type)),
            )),*],
            size_of::<$type>(),
        )
    }};
}

#[test]
fn header_structs_have_the_rust_layout_and_types() {
    let header = header_structs(&strip_comments(HEADER));
    let rust = BTreeMap::from([
        (
            "rustleaks_bytes".to_owned(),
            rust_layout!(Bytes, [ptr: *const u8, len: usize]),
        ),
        (
            "rustleaks_scan_args".to_owned(),
            rust_layout!(
                ScanArgs,
                [
                    path: *const u8,
                    path_len: usize,
                    overrides: u64,
                    decode_depth: u64,
                    base64_mode: u64,
                    redaction_percent: u64,
                    max_decoded_bytes: u64,
                    max_work_units: u64,
                    max_finding_records: u64,
                    max_finding_payload_bytes: u64,
                    max_collected_spans: u64,
                    max_normalization_bytes: u64,
                    deadline_ns: u64,
                    allow_comments: u8,
                ]
            ),
        ),
        (
            "rustleaks_rule_view".to_owned(),
            rust_layout!(
                RuleView,
                [
                    id: Bytes,
                    description: Bytes,
                    tags: *const Bytes,
                    tag_count: usize,
                    keywords: *const Bytes,
                    keyword_count: usize,
                ]
            ),
        ),
        (
            "rustleaks_finding_view".to_owned(),
            rust_layout!(
                FindingView,
                [
                    rule_id: Bytes,
                    description: Bytes,
                    tags: *const Bytes,
                    tag_count: usize,
                    secret: Bytes,
                    match_text: Bytes,
                    line: Bytes,
                    path: Bytes,
                    start_line: u64,
                    end_line: u64,
                    start_column: u64,
                    end_column: u64,
                    secret_start: u64,
                    secret_end: u64,
                    match_start: u64,
                    match_end: u64,
                    entropy: f64,
                    secret_range_exact: u8,
                    match_range_exact: u8,
                ]
            ),
        ),
        (
            "rustleaks_status_view".to_owned(),
            rust_layout!(
                StatusView,
                [
                    termination: i32,
                    budget: i32,
                    limit: u64,
                    consumed: u64,
                    requested: u64,
                    decoded_bytes: u64,
                    work_units: u64,
                    finding_records: u64,
                    finding_payload_bytes: u64,
                    collected_spans: u64,
                    normalization_bytes: u64,
                ]
            ),
        ),
    ]);
    assert_eq!(header, rust);
}

#[test]
fn header_parsers_reject_what_they_cannot_read() {
    assert_eq!(c_type("*mut *const u8"), "const uint8_t * *");
    assert_eq!(c_type("*const EngineHandle"), "const rustleaks_engine *");
    assert_eq!(c_type("*mut *mut Options"), "rustleaks_options * *");
    assert_eq!(c_type("* const Bytes"), "const rustleaks_bytes *");
    assert_eq!(c_type("f64"), "double");
    assert_eq!(normalize("const uint8_t **x"), "const uint8_t * * x");
    assert!(std::panic::catch_unwind(|| c_type("String")).is_err());
}
