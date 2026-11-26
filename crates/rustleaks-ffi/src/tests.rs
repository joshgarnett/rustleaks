//! Unit tests of the exports, through the safe harness and through raw
//! calls with bad arguments.

use std::ptr;
use std::sync::OnceLock;

use crate::abi::{
    ABI_VERSION, BUDGET_FINDING_RECORDS, BUDGET_NONE, ERROR_ABI_MISMATCH, ERROR_CONFIG,
    ERROR_INPUT_TOO_LARGE, ERROR_INVALID_ARGUMENT, ERROR_PANIC, ERROR_RULE_SELECTION, FindingView,
    OPTION_ALLOW_COMMENTS, OPTION_MAX_FINDING_RECORDS, OPTION_MAX_INPUT_BYTES,
    OPTION_SCAN_ON_CALLER_THREAD, OPTION_WORKERS, RuleView, SCAN_SET_ALL, SCAN_SET_DEADLINE,
    SCAN_SET_MAX_FINDING_RECORDS, STATUS_OK, StatusView, TERMINATION_BUDGET, TERMINATION_CANCELLED,
    TERMINATION_COMPLETE, TERMINATION_DEADLINE, UNLIMITED,
};
use crate::exports::{
    rustleaks_abi_version, rustleaks_cancel_free, rustleaks_cancel_new, rustleaks_cancel_set,
    rustleaks_engine_free, rustleaks_engine_max_input_bytes, rustleaks_engine_new,
    rustleaks_engine_rule, rustleaks_engine_rule_count, rustleaks_engine_workers,
    rustleaks_error_free, rustleaks_error_kind, rustleaks_error_message,
    rustleaks_options_add_rule_id, rustleaks_options_free, rustleaks_options_new,
    rustleaks_options_set_bool, rustleaks_options_set_config, rustleaks_options_set_u64,
    rustleaks_result_count, rustleaks_result_finding, rustleaks_result_free,
    rustleaks_result_status, rustleaks_scan, rustleaks_version,
};
use crate::handles::EngineHandle;
use crate::harness::{
    self, Cancel, Engine, Error, Finding, Options, empty_finding_view, scan_args,
};

/// The input that makes a scan panic after it took a scratch value.
const PANIC_INPUT: &[u8] = b"rustleaks-ffi synthetic scan panic";

/// Panics when `input` is [`PANIC_INPUT`]. Only test builds call this.
pub(crate) fn panic_if_requested(input: &[u8]) {
    assert!(input != PANIC_INPUT, "synthetic scan panic");
}

const TOKEN_CONFIG: &[u8] = br#"
[[rules]]
id = "token"
description = "A synthetic token"
regex = '''TOKEN'''
keywords = ["token"]
tags = ["synthetic", "test"]
"#;

fn engine_with(config: &[u8], setup: impl FnOnce(&mut Options)) -> Result<Engine, Error> {
    let mut options = Options::new()?;
    options.set_config(config)?;
    setup(&mut options);
    Engine::new(&options)
}

/// A new engine with one synthetic rule. Each test frees its own engine, so
/// Miri sees every scan thread joined.
fn token_engine() -> Engine {
    engine_with(TOKEN_CONFIG, |_| {}).unwrap()
}

/// The shared engine with every built-in rule. Tests that use it do not run
/// under Miri.
fn builtin_engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::new(&Options::new().unwrap()).unwrap())
}

#[test]
fn identity_reports_the_abi_number_and_crate_version() {
    assert_eq!(
        harness::library_identity(),
        (ABI_VERSION, env!("CARGO_PKG_VERSION").to_owned())
    );
}

#[test]
fn options_reject_another_abi_number() {
    let mut handle = ptr::without_provenance_mut(1);
    // SAFETY: the out pointer is a valid local.
    let status = unsafe { rustleaks_options_new(ABI_VERSION + 1, &raw mut handle) };
    assert_eq!(status, ERROR_ABI_MISMATCH);
    assert!(handle.is_null(), "the out parameter is cleared on failure");
    assert_eq!(Options::with_abi(0).unwrap_err().kind, ERROR_ABI_MISMATCH);
}

#[test]
fn null_handles_and_out_pointers_are_invalid_arguments() {
    let engine = token_engine();
    let mut count = 0_usize;
    let mut status_view = StatusView::default();
    let mut finding_view = empty_finding_view();
    let mut rule_view = RuleView {
        id: crate::abi::Bytes::EMPTY,
        description: crate::abi::Bytes::EMPTY,
        tags: ptr::null(),
        tag_count: 0,
        keywords: ptr::null(),
        keyword_count: 0,
    };
    let mut kind = 0;
    let mut text = ptr::null();
    let mut len = 0;
    let invalid = ERROR_INVALID_ARGUMENT;
    // SAFETY: every pointer is null, a valid local, or a live handle.
    unsafe {
        assert_eq!(rustleaks_abi_version(ptr::null_mut()), invalid);
        assert_eq!(rustleaks_version(ptr::null_mut(), &raw mut len), invalid);
        assert_eq!(rustleaks_version(&raw mut text, ptr::null_mut()), invalid);
        assert_eq!(rustleaks_options_new(ABI_VERSION, ptr::null_mut()), invalid);
        assert_eq!(
            rustleaks_options_set_config(ptr::null_mut(), ptr::null(), 0),
            invalid
        );
        assert_eq!(
            rustleaks_options_add_rule_id(ptr::null_mut(), ptr::null(), 0),
            invalid
        );
        assert_eq!(rustleaks_options_set_u64(ptr::null_mut(), 1, 1), invalid);
        assert_eq!(rustleaks_options_set_bool(ptr::null_mut(), 1, 1), invalid);
        assert_eq!(
            rustleaks_engine_workers(ptr::null(), &raw mut count),
            invalid
        );
        assert_eq!(
            rustleaks_engine_workers(engine.raw(), ptr::null_mut()),
            invalid
        );
        let mut limit = 0_u64;
        assert_eq!(
            rustleaks_engine_max_input_bytes(ptr::null(), &raw mut limit),
            invalid
        );
        assert_eq!(
            rustleaks_engine_max_input_bytes(engine.raw(), ptr::null_mut()),
            invalid
        );
        assert_eq!(
            rustleaks_engine_rule_count(ptr::null(), &raw mut count),
            invalid
        );
        assert_eq!(
            rustleaks_engine_rule(ptr::null(), 0, &raw mut rule_view),
            invalid
        );
        assert_eq!(
            rustleaks_engine_rule(engine.raw(), 0, ptr::null_mut()),
            invalid
        );
        assert_eq!(
            rustleaks_engine_rule(engine.raw(), 1, &raw mut rule_view),
            invalid
        );
        assert_eq!(rustleaks_cancel_new(ptr::null_mut()), invalid);
        assert_eq!(rustleaks_cancel_set(ptr::null()), invalid);
        assert_eq!(
            rustleaks_result_status(ptr::null(), &raw mut status_view),
            invalid
        );
        assert_eq!(rustleaks_result_count(ptr::null(), &raw mut count), invalid);
        assert_eq!(
            rustleaks_result_finding(ptr::null(), 0, &raw mut finding_view),
            invalid
        );
        assert_eq!(rustleaks_error_kind(ptr::null(), &raw mut kind), invalid);
        assert_eq!(
            rustleaks_error_message(ptr::null(), &raw mut text, &raw mut len),
            invalid
        );
        // Freeing null is allowed.
        assert_eq!(rustleaks_options_free(ptr::null_mut()), STATUS_OK);
        assert_eq!(rustleaks_engine_free(ptr::null_mut()), STATUS_OK);
        assert_eq!(rustleaks_cancel_free(ptr::null_mut()), STATUS_OK);
        assert_eq!(rustleaks_result_free(ptr::null_mut()), STATUS_OK);
        assert_eq!(rustleaks_error_free(ptr::null_mut()), STATUS_OK);
    }
}

#[test]
fn engine_new_and_scan_clear_their_out_parameters_and_report_errors() {
    let mut engine = ptr::without_provenance_mut(1);
    let mut error = ptr::without_provenance_mut(1);
    // SAFETY: the out pointers are valid locals and the options pointer is
    // null.
    let status = unsafe { rustleaks_engine_new(ptr::null(), &raw mut engine, &raw mut error) };
    assert_eq!(status, ERROR_INVALID_ARGUMENT);
    assert!(engine.is_null());
    assert!(!error.is_null());
    let mut kind = 0;
    // SAFETY: `error` is a new error handle, freed once.
    unsafe {
        assert_eq!(rustleaks_error_kind(error, &raw mut kind), STATUS_OK);
        assert_eq!(rustleaks_error_free(error), STATUS_OK);
    }
    assert_eq!(kind, ERROR_INVALID_ARGUMENT);

    // Without an error pointer the call still fails cleanly.
    // SAFETY: as above.
    let status = unsafe { rustleaks_engine_new(ptr::null(), &raw mut engine, ptr::null_mut()) };
    assert_eq!(status, ERROR_INVALID_ARGUMENT);

    let mut result = ptr::without_provenance_mut(1);
    let mut error = ptr::without_provenance_mut(1);
    // SAFETY: the engine is live, the input is null with length 0, and the
    // out pointers are valid locals.
    let status = unsafe {
        rustleaks_scan(
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            &raw mut result,
            &raw mut error,
        )
    };
    assert_eq!(status, ERROR_INVALID_ARGUMENT);
    assert!(result.is_null());
    // SAFETY: `error` is a new error handle, freed once.
    unsafe { assert_eq!(rustleaks_error_free(error), STATUS_OK) };
}

#[test]
fn null_bytes_are_valid_only_with_length_zero() {
    let engine = token_engine();
    // SAFETY: a null input pointer with length 0 is allowed.
    let outcome = unsafe { engine.scan_raw(ptr::null(), 0, None, None) }.unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_COMPLETE);
    assert!(outcome.findings.is_empty());

    // SAFETY: the library checks a null pointer before reading it.
    let error = unsafe { engine.scan_raw(ptr::null(), 3, None, None) }.unwrap_err();
    assert_eq!(error.kind, ERROR_INVALID_ARGUMENT);

    let mut args = scan_args(b"").raw();
    args.path_len = 4;
    // SAFETY: the input is a valid slice; the library checks the null
    // path before reading it.
    let error = unsafe { engine.scan_raw(b"TOKEN".as_ptr(), 5, Some(&args), None) }.unwrap_err();
    assert_eq!(error.kind, ERROR_INVALID_ARGUMENT);

    let mut options = Options::new().unwrap();
    // SAFETY: the options handle is live; the pointers are null.
    unsafe {
        let raw = options.raw();
        assert_eq!(rustleaks_options_set_config(raw, ptr::null(), 0), STATUS_OK);
        assert_eq!(
            rustleaks_options_set_config(raw, ptr::null(), 1),
            ERROR_INVALID_ARGUMENT
        );
        assert_eq!(
            rustleaks_options_add_rule_id(raw, ptr::null(), 2),
            ERROR_INVALID_ARGUMENT
        );
    }
    // An empty configuration has no rules.
    options.set_config(b"").unwrap();
    let empty = Engine::new(&options).unwrap();
    assert!(empty.rules().is_empty());
    assert!(
        empty
            .scan(b"TOKEN", None, None)
            .unwrap()
            .findings
            .is_empty()
    );
}

#[test]
fn options_check_keys_and_boolean_values() {
    let mut options = Options::new().unwrap();
    assert_eq!(
        options.set_u64(0, 1).unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
    assert_eq!(
        options.set_u64(99, 1).unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
    assert_eq!(
        options.set_bool(OPTION_ALLOW_COMMENTS, 2).unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
    assert_eq!(
        options.set_bool(9, 1).unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
    assert_eq!(
        options.add_rule_id(b"\xffid").unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
    options.set_bool(OPTION_ALLOW_COMMENTS, 0).unwrap();
    options.set_u64(OPTION_WORKERS, 3).unwrap();
    options.set_config(TOKEN_CONFIG).unwrap();
    assert_eq!(Engine::new(&options).unwrap().workers(), 3);
}

#[test]
fn scan_arguments_reject_unknown_bits_and_values() {
    let engine = token_engine();
    let mut args = scan_args(b"");
    args.overrides = SCAN_SET_ALL + 1;
    assert_eq!(
        engine.scan(b"x", Some(&args), None).unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
    let mut args = scan_args(b"");
    args.allow_comments = 2;
    assert_eq!(
        engine.scan(b"x", Some(&args), None).unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
    let mut args = scan_args(b"");
    args.overrides = crate::abi::SCAN_SET_BASE64_MODE;
    args.base64_mode = 7;
    assert_eq!(
        engine.scan(b"x", Some(&args), None).unwrap_err().kind,
        ERROR_INVALID_ARGUMENT
    );
}

#[test]
fn findings_carry_every_field_and_the_given_path() {
    let engine = token_engine();
    let input = b"a TOKEN\nTOKEN\n";
    let outcome = engine
        .scan(input, Some(&scan_args(br"dir\file.txt")), None)
        .unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_COMPLETE);
    assert_eq!(outcome.status.budget, BUDGET_NONE);
    assert_eq!(outcome.status.finding_records, 2);
    let [first, second] = outcome.findings.as_slice() else {
        panic!("two findings");
    };
    assert_eq!(first.rule_id, b"token");
    assert_eq!(first.description, b"A synthetic token");
    assert_eq!(first.tags, [b"synthetic".to_vec(), b"test".to_vec()]);
    assert_eq!(first.secret, b"TOKEN");
    assert_eq!(first.match_text, b"TOKEN");
    assert_eq!(first.line, b"a TOKEN");
    assert_eq!(first.path, br"dir\file.txt");
    assert_eq!(
        (
            first.start_line,
            first.end_line,
            first.start_column,
            first.end_column
        ),
        (1, 1, 3, 7)
    );
    assert_eq!(first.secret_range, Some((2, 7)));
    assert_eq!(first.match_range, Some((2, 7)));
    // Five different bytes: log2(5) bits.
    assert!(
        (first.entropy - 5_f64.log2()).abs() < 1e-6,
        "{}",
        first.entropy
    );
    assert_eq!(second.line, b"\nTOKEN");
    assert_eq!(
        (
            second.start_line,
            second.end_line,
            second.start_column,
            second.end_column
        ),
        (2, 2, 2, 6)
    );
    assert_eq!(second.secret_range, Some((8, 13)));
}

#[test]
fn findings_on_one_long_line_share_one_line_view() {
    let engine = token_engine();
    let mut input = b"TOKEN ".repeat(1000);
    input.push(b'\n');
    let outcome = engine.scan(&input, None, None).unwrap();
    assert_eq!(outcome.findings.len(), 1000);
    let first = outcome.findings[0].line_view;
    assert_eq!(first.1, input.len() - 1);
    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.line_view == first)
    );
}

#[test]
fn rules_list_every_reporting_rule_in_report_order() {
    let engine = engine_with(
        br#"
[[rules]]
id = "second"
regex = '''B'''
keywords = ["b", "bb"]

[[rules]]
id = "first"
description = "First"
regex = '''A'''
tags = ["t"]
"#,
        |_| {},
    )
    .unwrap();
    let rules = engine.rules();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].id, b"second");
    assert_eq!(rules[0].keywords, [b"b".to_vec(), b"bb".to_vec()]);
    assert!(rules[0].tags.is_empty());
    assert_eq!(rules[1].id, b"first");
    assert_eq!(rules[1].description, b"First");
    assert_eq!(rules[1].tags, [b"t".to_vec()]);
}

#[test]
fn configuration_errors_keep_the_core_message() {
    let error = engine_with(b"[extend]\npath = \"base.toml\"\n", |_| {}).unwrap_err();
    assert_eq!(error.kind, ERROR_CONFIG);
    assert!(
        error
            .message
            .contains("external configuration I/O is disabled"),
        "{}",
        error.message
    );

    let error = engine_with(b"title = \"\xff\"", |_| {}).unwrap_err();
    assert_eq!(error.kind, ERROR_CONFIG);
    assert!(error.message.contains("UTF-8"));

    let error = engine_with(
        b"[[rules]]\nid = \"bad\"\nregex = '''(unclosed'''\n",
        |_| {},
    )
    .unwrap_err();
    assert_eq!(error.kind, ERROR_CONFIG);
    assert!(error.message.contains("(unclosed"), "{}", error.message);

    let error = engine_with(TOKEN_CONFIG, |options| {
        options.add_rule_id(b"missing").unwrap();
    })
    .unwrap_err();
    assert_eq!(error.kind, ERROR_RULE_SELECTION);
    assert!(error.message.contains("missing"));
}

#[test]
fn input_limit_is_inclusive_and_checked_before_reading() {
    let engine = engine_with(TOKEN_CONFIG, |options| {
        options.set_u64(OPTION_MAX_INPUT_BYTES, 5).unwrap();
    })
    .unwrap();
    assert_eq!(engine.max_input_bytes(), 5);
    assert_eq!(
        token_engine().max_input_bytes(),
        crate::handles::DEFAULT_MAX_INPUT_BYTES
    );
    assert_eq!(crate::handles::DEFAULT_MAX_INPUT_BYTES, 10_000_000);
    assert_eq!(engine.scan(b"TOKEN", None, None).unwrap().findings.len(), 1);
    let error = engine.scan(b"TOKEN!", None, None).unwrap_err();
    assert_eq!(error.kind, ERROR_INPUT_TOO_LARGE);
    assert_eq!(
        error.message,
        "input is 6 bytes, more than the limit of 5 bytes"
    );
    // SAFETY: the library rejects the length before it reads the pointer.
    let error = unsafe { engine.scan_raw(ptr::null(), 6, None, None) }.unwrap_err();
    assert_eq!(error.kind, ERROR_INPUT_TOO_LARGE);

    let unlimited = engine_with(TOKEN_CONFIG, |options| {
        options.set_u64(OPTION_MAX_INPUT_BYTES, UNLIMITED).unwrap();
    })
    .unwrap();
    assert_eq!(unlimited.max_input_bytes(), UNLIMITED);
    assert!(unlimited.scan(b"TOKEN!", None, None).is_ok());
}

#[test]
fn finding_record_budget_stops_the_scan_with_its_numbers() {
    let engine = engine_with(TOKEN_CONFIG, |options| {
        options.set_u64(OPTION_MAX_FINDING_RECORDS, 1).unwrap();
    })
    .unwrap();
    let outcome = engine.scan(b"TOKEN TOKEN", None, None).unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_BUDGET);
    assert_eq!(outcome.status.budget, BUDGET_FINDING_RECORDS);
    assert_eq!(
        (
            outcome.status.limit,
            outcome.status.consumed,
            outcome.status.requested
        ),
        (1, 1, 1)
    );
    let mut args = scan_args(b"");
    args.overrides = SCAN_SET_MAX_FINDING_RECORDS;
    args.max_finding_records = UNLIMITED;
    let outcome = engine.scan(b"TOKEN TOKEN", Some(&args), None).unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_COMPLETE);
    assert_eq!(outcome.findings.len(), 2);
}

#[test]
fn cancel_and_deadline_stop_a_scan_and_a_complete_scan_stays_complete() {
    let engine = token_engine();
    let cancel = Cancel::new();
    let outcome = engine.scan(b"TOKEN", None, Some(&cancel)).unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_COMPLETE);
    cancel.set();
    let outcome = engine.scan(b"TOKEN", None, Some(&cancel)).unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_CANCELLED);
    assert!(outcome.findings.is_empty());

    let mut args = scan_args(b"");
    args.overrides = SCAN_SET_DEADLINE;
    args.deadline_ns = 0;
    let outcome = engine.scan(b"TOKEN", Some(&args), None).unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_DEADLINE);
    // A set flag wins over a passed deadline.
    let outcome = engine.scan(b"TOKEN", Some(&args), Some(&cancel)).unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_CANCELLED);

    args.deadline_ns = u64::MAX;
    let outcome = engine.scan(b"TOKEN", Some(&args), None).unwrap();
    assert_eq!(outcome.status.termination, TERMINATION_COMPLETE);
    assert_eq!(outcome.findings.len(), 1);
}

#[test]
#[cfg_attr(miri, ignore = "scans many inputs")]
fn cancel_set_from_another_thread_stops_later_scans() {
    let engine = token_engine();
    let cancel = Cancel::new();
    let input = b"TOKEN x\n".repeat(20_000);
    std::thread::scope(|scope| {
        let scanner = scope.spawn(|| {
            let mut seen = Vec::new();
            loop {
                let outcome = engine.scan(&input, None, Some(&cancel)).unwrap();
                seen.push(outcome.status.termination);
                if outcome.status.termination == TERMINATION_CANCELLED {
                    return seen;
                }
            }
        });
        cancel.set();
        let seen = scanner.join().unwrap();
        assert_eq!(seen.last(), Some(&TERMINATION_CANCELLED));
        assert!(seen.iter().all(|termination| {
            [TERMINATION_COMPLETE, TERMINATION_CANCELLED].contains(termination)
        }));
    });
}

#[test]
fn a_panicking_scan_drops_its_scratch_and_returns_an_internal_error() {
    for caller_thread in [0, 1] {
        let engine = engine_with(TOKEN_CONFIG, |options| {
            options
                .set_bool(OPTION_SCAN_ON_CALLER_THREAD, caller_thread)
                .unwrap();
        })
        .unwrap();
        let handle = engine.handle();
        assert_eq!(handle.has_scan_threads(), caller_thread == 0);
        assert_eq!(handle.pooled_scratch(), 0);
        engine.scan(b"TOKEN", None, None).unwrap();
        assert_eq!(handle.pooled_scratch(), 1);

        let error = engine.scan(PANIC_INPUT, None, None).unwrap_err();
        assert_eq!(error.kind, ERROR_PANIC);
        assert_eq!(error.message, "rustleaks caught an internal panic");
        assert_eq!(handle.pooled_scratch(), 0, "the scratch value was dropped");

        // The engine still works and makes a new scratch value.
        assert_eq!(engine.scan(b"TOKEN", None, None).unwrap().findings.len(), 1);
        assert_eq!(handle.pooled_scratch(), 1);
    }
}

#[test]
fn scans_on_the_calling_thread_give_the_same_outcome() {
    let threaded = token_engine();
    let inline = engine_with(TOKEN_CONFIG, |options| {
        options.set_bool(OPTION_SCAN_ON_CALLER_THREAD, 1).unwrap();
    })
    .unwrap();
    let input = b"a TOKEN\nb TOKEN # rustleaks:allow\nTOKEN\n";
    let left = threaded.scan(input, Some(&scan_args(b"p")), None).unwrap();
    let right = inline.scan(input, Some(&scan_args(b"p")), None).unwrap();
    assert_eq!(left.status, right.status);
    assert_eq!(left.findings.len(), 2);
    for (left, right) in left.findings.iter().zip(&right.findings) {
        assert_eq!(
            Finding {
                line_view: (0, 0),
                ..left.clone()
            },
            Finding {
                line_view: (0, 0),
                ..right.clone()
            }
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "scans on many threads")]
fn concurrent_scans_share_one_engine_and_keep_at_most_one_scratch_per_worker() {
    let engine = engine_with(TOKEN_CONFIG, |options| {
        options.set_u64(OPTION_WORKERS, 2).unwrap();
    })
    .unwrap();
    let input = b"x TOKEN\n".repeat(64);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..16 {
                    let outcome = engine.scan(&input, None, None).unwrap();
                    assert_eq!(outcome.findings.len(), 64);
                }
            });
        }
    });
    let handle: &EngineHandle = engine.handle();
    assert!(handle.pooled_scratch() <= 2);
}

#[test]
fn allow_comments_follow_the_engine_option_and_the_scan_override() {
    let engine = token_engine();
    let input = b"TOKEN # rustleaks:allow\nTOKEN # gitleaks:allow\nTOKEN\n";
    assert_eq!(engine.scan(input, None, None).unwrap().findings.len(), 1);
    let mut args = scan_args(b"");
    args.overrides = crate::abi::SCAN_SET_ALLOW_COMMENTS;
    args.allow_comments = 0;
    assert_eq!(
        engine
            .scan(input, Some(&args), None)
            .unwrap()
            .findings
            .len(),
        3
    );

    let reporting = engine_with(TOKEN_CONFIG, |options| {
        options.set_bool(OPTION_ALLOW_COMMENTS, 0).unwrap();
    })
    .unwrap();
    assert_eq!(reporting.scan(input, None, None).unwrap().findings.len(), 3);
}

#[test]
#[cfg_attr(miri, ignore = "loads every built-in rule")]
fn builtin_rules_load_by_default_and_list_in_report_order() {
    let rules = builtin_engine().rules();
    assert!(rules.len() > 200);
    assert!(rules.iter().any(|rule| rule.id == b"pkcs12-file"));
    let mut ids = rules.iter().map(|rule| rule.id.clone()).collect::<Vec<_>>();
    let listed = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), listed, "each rule is listed once");
}

/// Thread stack size that Go gives a cgo thread on musl, the smallest that
/// a caller is likely to use.
const SMALL_STACK: usize = 128 << 10;

fn on_small_stack<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(SMALL_STACK)
            .spawn_scoped(scope, work)
            .unwrap()
            .join()
            .unwrap()
    })
}

#[test]
#[cfg_attr(miri, ignore = "compiles a deep pattern")]
fn a_rule_with_200_nested_groups_builds_and_scans_on_a_128_kib_stack() {
    // 200 groups is the most that core compiles on the thread that builds
    // the engine or searches. An unoptimized build needs more than 128 KiB
    // for it, so this passes only because the library builds and scans on
    // its own threads.
    let pattern = format!("{}a{}", "(".repeat(200), ")".repeat(200));
    let config = format!("[[rules]]\nid = \"deep\"\nregex = '''{pattern}'''\n");
    let findings = on_small_stack(|| {
        let engine = engine_with(config.as_bytes(), |_| {}).unwrap();
        engine.scan(b"xax", None, None).unwrap().findings
    });
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].match_text, b"a");
}

#[test]
#[cfg_attr(miri, ignore = "loads every built-in rule")]
fn builtin_rules_build_and_scan_on_a_128_kib_stack() {
    // Every keyword in the input makes the scan compile every rule's
    // pattern on this thread.
    let outcome = on_small_stack(|| {
        let engine = Engine::new(&Options::new().unwrap()).unwrap();
        let mut input = Vec::new();
        for rule in engine.rules() {
            for keyword in rule.keywords {
                input.extend_from_slice(&keyword);
                input.extend_from_slice(b" = \"x\"\n");
            }
        }
        let mut args = scan_args(b"config/app.env");
        args.overrides = crate::abi::SCAN_SET_DECODE_DEPTH;
        args.decode_depth = 5;
        engine.scan(&input, Some(&args), None).unwrap()
    });
    assert_eq!(outcome.status.termination, TERMINATION_COMPLETE);
}

#[test]
#[cfg(windows)]
fn windows_paths_reach_path_rules_in_both_spellings() {
    let engine = engine_with(
        b"[[rules]]\nid = \"secrets-dir\"\npath = '''(^|/)secrets/'''\n",
        |_| {},
    )
    .unwrap();
    let outcome = engine
        .scan(b"", Some(&scan_args(br"app\secrets\key.txt")), None)
        .unwrap();
    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].path, br"app\secrets\key.txt");
}

#[test]
fn views_have_null_pointers_for_empty_lists() {
    let engine = token_engine();
    let mut view = empty_finding_view();
    let mut result = ptr::null_mut();
    let mut error = ptr::null_mut();
    // SAFETY: the engine is live, the input is a valid slice and the out
    // pointers are valid locals. The result is freed once.
    unsafe {
        assert_eq!(
            rustleaks_scan(
                engine.raw(),
                b"TOKEN".as_ptr(),
                5,
                ptr::null(),
                ptr::null(),
                &raw mut result,
                &raw mut error,
            ),
            STATUS_OK
        );
        assert_eq!(
            rustleaks_result_finding(result, 0, &raw mut view),
            STATUS_OK
        );
        assert!(view.path.ptr.is_null() && view.path.len == 0);
        assert!(!view.tags.is_null() && view.tag_count == 2);
        assert_eq!(
            rustleaks_result_finding(result, 1, &raw mut view),
            ERROR_INVALID_ARGUMENT
        );
        assert_eq!(rustleaks_result_free(result), STATUS_OK);
    }
    let _: FindingView = view;
}

#[test]
fn the_fuzz_harness_accepts_short_and_empty_inputs() {
    harness::exercise(b"");
    harness::exercise(&[0xff; 64]);
    let mut input = vec![0, 64];
    input.extend_from_slice(&TOKEN_CONFIG[..64]);
    input.extend_from_slice(b"\x00\x00TOKEN");
    harness::exercise(&input);
}

#[test]
fn every_error_kind_is_listed_once() {
    let mut kinds = harness::ERROR_KINDS.to_vec();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(kinds, (1..=8).collect::<Vec<_>>());
}

#[test]
fn cancel_handles_can_be_made_set_and_freed() {
    let mut cancel = ptr::without_provenance_mut(1);
    // SAFETY: the out pointer is a valid local; the handle is freed once.
    unsafe {
        assert_eq!(rustleaks_cancel_new(&raw mut cancel), STATUS_OK);
        assert_eq!(rustleaks_cancel_set(cancel), STATUS_OK);
        assert_eq!(rustleaks_cancel_set(cancel), STATUS_OK);
        assert_eq!(rustleaks_cancel_free(cancel), STATUS_OK);
    }
}

#[test]
fn rule_count_and_workers_match_the_harness_views() {
    let engine = token_engine();
    let mut count = 0;
    let mut workers = 0;
    // SAFETY: the engine is live and the out pointers are valid locals.
    unsafe {
        assert_eq!(
            rustleaks_engine_rule_count(engine.raw(), &raw mut count),
            STATUS_OK
        );
        assert_eq!(
            rustleaks_engine_workers(engine.raw(), &raw mut workers),
            STATUS_OK
        );
    }
    assert_eq!(count, 1);
    assert!(workers >= 1);
    let raw_engine: *mut EngineHandle = ptr::null_mut();
    let mut error = ptr::null_mut();
    let mut out = raw_engine;
    let mut options = ptr::null_mut();
    // SAFETY: the out pointers are valid locals; every handle is freed once.
    unsafe {
        assert_eq!(
            rustleaks_options_new(ABI_VERSION, &raw mut options),
            STATUS_OK
        );
        assert_eq!(
            rustleaks_options_set_config(options, TOKEN_CONFIG.as_ptr(), TOKEN_CONFIG.len()),
            STATUS_OK
        );
        assert_eq!(
            rustleaks_engine_new(options, &raw mut out, &raw mut error),
            STATUS_OK
        );
        assert!(error.is_null());
        assert_eq!(rustleaks_options_free(options), STATUS_OK);
        assert_eq!(rustleaks_engine_free(out), STATUS_OK);
    }
}

#[test]
fn a_null_error_pointer_returns_only_the_status() {
    let mut options = Options::new().unwrap();
    options.set_config(TOKEN_CONFIG).unwrap();
    let mut bad = Options::new().unwrap();
    bad.set_config(b"[extend]\npath = \"base.toml\"\n").unwrap();
    let mut engine = ptr::null_mut();
    let mut result = ptr::null_mut();
    // SAFETY: the options handles are live, the out pointers are valid
    // locals, the error pointers are null, and every handle made here is
    // freed once.
    unsafe {
        // Success without an error pointer.
        let status = rustleaks_engine_new(options.raw(), &raw mut engine, ptr::null_mut());
        assert_eq!(status, STATUS_OK);
        assert!(!engine.is_null());
        let status = rustleaks_scan(
            engine,
            b"TOKEN".as_ptr(),
            5,
            ptr::null(),
            ptr::null(),
            &raw mut result,
            ptr::null_mut(),
        );
        assert_eq!(status, STATUS_OK);
        assert!(!result.is_null());
        assert_eq!(rustleaks_result_free(result), STATUS_OK);

        // Failures without an error pointer: only the status comes back.
        let status = rustleaks_scan(
            engine,
            ptr::null(),
            5,
            ptr::null(),
            ptr::null(),
            &raw mut result,
            ptr::null_mut(),
        );
        assert_eq!(status, ERROR_INVALID_ARGUMENT);
        assert!(result.is_null());
        assert_eq!(rustleaks_engine_free(engine), STATUS_OK);

        let status = rustleaks_engine_new(bad.raw(), &raw mut engine, ptr::null_mut());
        assert_eq!(status, ERROR_CONFIG);
        assert!(engine.is_null());
    }
}

#[test]
fn a_misaligned_error_pointer_is_invalid() {
    let options = Options::new().unwrap();
    let mut engine = ptr::null_mut();
    let misaligned = ptr::without_provenance_mut::<*mut crate::handles::FfiError>(1);
    // SAFETY: the library rejects the misaligned error pointer before it
    // writes through it; the other pointers are valid.
    let status = unsafe { rustleaks_engine_new(options.raw(), &raw mut engine, misaligned) };
    assert_eq!(status, ERROR_INVALID_ARGUMENT);
    assert!(engine.is_null());
}
