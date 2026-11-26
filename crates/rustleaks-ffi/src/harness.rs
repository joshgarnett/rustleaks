//! A safe Rust client of the C ABI, for the contract tests and the fuzz
//! target. It calls the exported functions the way the Go and Python
//! wrappers do: it checks the ABI number, copies every view into owned
//! values and frees each handle once.
//!
//! This module is not a supported Rust API.

use std::ptr::{self, NonNull};

use crate::abi::{
    ABI_VERSION, Bytes, ERROR_ABI_MISMATCH, ERROR_CLOSED, ERROR_CONFIG, ERROR_ENGINE,
    ERROR_INPUT_TOO_LARGE, ERROR_INVALID_ARGUMENT, ERROR_PANIC, ERROR_RULE_SELECTION, FindingView,
    RuleView, STATUS_OK, ScanArgs, StatusView,
};
use crate::cancel::CancelHandle;
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
use crate::handles::{self, EngineHandle, FfiError, ResultHandle};

/// Every error kind that a library call can return.
pub const ERROR_KINDS: [i32; 8] = [
    ERROR_INVALID_ARGUMENT,
    ERROR_ABI_MISMATCH,
    ERROR_CONFIG,
    ERROR_RULE_SELECTION,
    ERROR_ENGINE,
    ERROR_INPUT_TOO_LARGE,
    ERROR_CLOSED,
    ERROR_PANIC,
];

/// Copies the bytes of a view.
///
/// # Safety
///
/// `bytes` must come from this library and its owner must still be live.
unsafe fn copy(bytes: Bytes) -> Vec<u8> {
    if bytes.len == 0 {
        return Vec::new();
    }
    // SAFETY: the library gives a non-null pointer to `len` bytes for a
    // non-empty view, valid while the owner lives, as the caller guarantees.
    unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) }.to_vec()
}

/// Copies a list of views.
///
/// # Safety
///
/// `list` and `count` must come from one view of this library and its owner
/// must still be live.
unsafe fn copy_list(list: *const Bytes, count: usize) -> Vec<Vec<u8>> {
    if count == 0 {
        return Vec::new();
    }
    // SAFETY: the library gives a non-null pointer to `count` views for a
    // non-empty list, valid while the owner lives.
    let views = unsafe { std::slice::from_raw_parts(list, count) };
    views
        .iter()
        // SAFETY: each view comes from the same live owner.
        .map(|view| unsafe { copy(*view) })
        .collect()
}

/// An error returned through a `rustleaks_error` handle, or a bare status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The `ERROR_*` kind.
    pub kind: i32,
    /// The message, empty for a bare status.
    pub message: String,
}

impl Error {
    fn status(kind: i32) -> Self {
        Self {
            kind,
            message: String::new(),
        }
    }

    /// Takes over an error handle, copies it and frees it.
    ///
    /// # Safety
    ///
    /// `handle` must be null or a live error handle that no one else uses.
    unsafe fn take(status: i32, handle: *mut FfiError) -> Self {
        if handle.is_null() {
            return Self::status(status);
        }
        let mut kind = 0;
        let mut ptr = ptr::null();
        let mut len = 0;
        // SAFETY: `handle` is a live error handle and the out pointers are
        // valid locals.
        unsafe {
            assert_eq!(rustleaks_error_kind(handle, &raw mut kind), STATUS_OK);
            assert_eq!(
                rustleaks_error_message(handle, &raw mut ptr, &raw mut len),
                STATUS_OK
            );
        }
        // SAFETY: the message view belongs to the live error handle.
        let message = unsafe { copy(Bytes { ptr, len }) };
        // SAFETY: the handle is freed once, after its last use.
        assert_eq!(unsafe { rustleaks_error_free(handle) }, STATUS_OK);
        assert_eq!(kind, status, "the error kind is the returned status");
        Self {
            kind,
            message: String::from_utf8(message).expect("error messages are UTF-8"),
        }
    }
}

fn check(status: i32) -> Result<(), Error> {
    if status == STATUS_OK {
        Ok(())
    } else {
        Err(Error::status(status))
    }
}

/// Returns the library's ABI number and version.
#[must_use]
pub fn library_identity() -> (u32, String) {
    let mut abi = 0;
    let mut ptr = ptr::null();
    let mut len = 0;
    // SAFETY: the out pointers are valid locals.
    unsafe {
        assert_eq!(rustleaks_abi_version(&raw mut abi), STATUS_OK);
        assert_eq!(rustleaks_version(&raw mut ptr, &raw mut len), STATUS_OK);
    }
    // SAFETY: the version bytes live as long as the library.
    let version = unsafe { copy(Bytes { ptr, len }) };
    (
        abi,
        String::from_utf8(version).expect("the version is UTF-8"),
    )
}

/// An owned options handle.
#[derive(Debug)]
pub struct Options(*mut handles::Options);

impl Options {
    /// Creates options with the library's ABI number.
    ///
    /// # Errors
    ///
    /// Returns the status of `rustleaks_options_new`.
    pub fn new() -> Result<Self, Error> {
        Self::with_abi(ABI_VERSION)
    }

    /// Creates options with an ABI number that may be wrong.
    ///
    /// # Errors
    ///
    /// Returns the status of `rustleaks_options_new`.
    pub fn with_abi(abi: u32) -> Result<Self, Error> {
        let mut handle = ptr::null_mut();
        // SAFETY: the out pointer is a valid local.
        check(unsafe { rustleaks_options_new(abi, &raw mut handle) })?;
        assert!(!handle.is_null());
        Ok(Self(handle))
    }

    /// The raw handle, for tests that call the exports directly.
    #[must_use]
    pub const fn raw(&self) -> *mut handles::Options {
        self.0
    }

    /// Sets the TOML configuration.
    ///
    /// # Errors
    ///
    /// Returns the status of the call.
    pub fn set_config(&mut self, config: &[u8]) -> Result<(), Error> {
        // SAFETY: the handle is live and owned; the bytes are a valid slice.
        check(unsafe { rustleaks_options_set_config(self.0, config.as_ptr(), config.len()) })
    }

    /// Adds a rule ID.
    ///
    /// # Errors
    ///
    /// Returns the status of the call.
    pub fn add_rule_id(&mut self, id: &[u8]) -> Result<(), Error> {
        // SAFETY: the handle is live and owned; the bytes are a valid slice.
        check(unsafe { rustleaks_options_add_rule_id(self.0, id.as_ptr(), id.len()) })
    }

    /// Sets a numeric option.
    ///
    /// # Errors
    ///
    /// Returns the status of the call.
    pub fn set_u64(&mut self, key: u32, value: u64) -> Result<(), Error> {
        // SAFETY: the handle is live and owned.
        check(unsafe { rustleaks_options_set_u64(self.0, key, value) })
    }

    /// Sets a boolean option from a raw byte, which the library checks.
    ///
    /// # Errors
    ///
    /// Returns the status of the call.
    pub fn set_bool(&mut self, key: u32, value: u8) -> Result<(), Error> {
        // SAFETY: the handle is live and owned.
        check(unsafe { rustleaks_options_set_bool(self.0, key, value) })
    }
}

impl Drop for Options {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once.
        assert_eq!(unsafe { rustleaks_options_free(self.0) }, STATUS_OK);
    }
}

/// An owned cancel handle.
#[derive(Debug)]
pub struct Cancel(*mut CancelHandle);

// SAFETY: a cancel handle is an atomic flag; the library allows any thread
// to set it while scans read it.
unsafe impl Send for Cancel {}
// SAFETY: as above; shared use only calls `rustleaks_cancel_set`.
unsafe impl Sync for Cancel {}

impl Cancel {
    /// Creates a cancel handle.
    ///
    /// # Panics
    ///
    /// Panics if the library cannot create one.
    #[must_use]
    pub fn new() -> Self {
        let mut handle = ptr::null_mut();
        // SAFETY: the out pointer is a valid local.
        assert_eq!(unsafe { rustleaks_cancel_new(&raw mut handle) }, STATUS_OK);
        Self(handle)
    }

    /// Sets the handle.
    pub fn set(&self) {
        // SAFETY: the handle is live.
        assert_eq!(unsafe { rustleaks_cancel_set(self.0) }, STATUS_OK);
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Cancel {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once, after every scan that
        // borrowed it returned.
        assert_eq!(unsafe { rustleaks_cancel_free(self.0) }, STATUS_OK);
    }
}

/// A rule, copied out of an engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Rule ID.
    pub id: Vec<u8>,
    /// Description.
    pub description: Vec<u8>,
    /// Tags.
    pub tags: Vec<Vec<u8>>,
    /// Keywords.
    pub keywords: Vec<Vec<u8>>,
}

/// A finding, copied out of a result.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    /// Rule ID.
    pub rule_id: Vec<u8>,
    /// Description.
    pub description: Vec<u8>,
    /// Tags.
    pub tags: Vec<Vec<u8>>,
    /// Secret.
    pub secret: Vec<u8>,
    /// Matched text.
    pub match_text: Vec<u8>,
    /// Source line.
    pub line: Vec<u8>,
    /// Path given to the scan.
    pub path: Vec<u8>,
    /// First line.
    pub start_line: u64,
    /// Last line.
    pub end_line: u64,
    /// First column.
    pub start_column: u64,
    /// Last column.
    pub end_column: u64,
    /// Exact secret range in the input.
    pub secret_range: Option<(u64, u64)>,
    /// Exact match range in the input.
    pub match_range: Option<(u64, u64)>,
    /// Entropy of the secret.
    pub entropy: f64,
    /// Pointer and length of the line view, to check that findings on one
    /// line share it.
    pub line_view: (usize, usize),
}

/// A result, copied out of the library.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// Status view.
    pub status: StatusView,
    /// Findings in order.
    pub findings: Vec<Finding>,
}

/// An owned engine handle. Many threads can scan with it at once.
#[derive(Debug)]
pub struct Engine(NonNull<EngineHandle>);

// SAFETY: the library allows scans from many threads with one engine, and
// the engine is freed only when the owner drops it.
unsafe impl Send for Engine {}
// SAFETY: shared use only calls the thread-safe query and scan functions.
unsafe impl Sync for Engine {}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and freed once, after every scan that
        // borrowed it returned.
        assert_eq!(unsafe { rustleaks_engine_free(self.0.as_ptr()) }, STATUS_OK);
    }
}

impl Engine {
    /// Builds an engine.
    ///
    /// # Errors
    ///
    /// Returns the library error.
    pub fn new(options: &Options) -> Result<Self, Error> {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        // SAFETY: the options handle is live and the out pointers are valid
        // locals.
        let status = unsafe { rustleaks_engine_new(options.0, &raw mut handle, &raw mut error) };
        if status != STATUS_OK {
            assert!(handle.is_null());
            // SAFETY: on failure `error` is null or a new error handle.
            return Err(unsafe { Error::take(status, error) });
        }
        assert!(error.is_null());
        let handle = NonNull::new(handle).expect("a successful engine_new returns a handle");
        Ok(Self(handle))
    }

    /// The raw handle, for tests that call the exports directly.
    #[must_use]
    pub const fn raw(&self) -> *const EngineHandle {
        self.0.as_ptr()
    }

    /// The engine behind the handle, borrowed for as long as `self`.
    #[must_use]
    pub fn handle(&self) -> &EngineHandle {
        // SAFETY: `Engine::new` checked that the handle is not null, the
        // library made it with `Box::into_raw`, and this value frees it only
        // when it drops, so it stays live and unchanged while `self` is
        // borrowed.
        unsafe { self.0.as_ref() }
    }

    /// The worker count.
    #[must_use]
    pub fn workers(&self) -> usize {
        let mut workers = 0;
        // SAFETY: the handle is live and the out pointer is a valid local.
        let status = unsafe { rustleaks_engine_workers(self.0.as_ptr(), &raw mut workers) };
        assert_eq!(status, STATUS_OK);
        workers
    }

    /// The inclusive input limit.
    #[must_use]
    pub fn max_input_bytes(&self) -> u64 {
        let mut limit = 0;
        // SAFETY: the handle is live and the out pointer is a valid local.
        let status = unsafe { rustleaks_engine_max_input_bytes(self.0.as_ptr(), &raw mut limit) };
        assert_eq!(status, STATUS_OK);
        limit
    }

    /// The rules, in report order.
    #[must_use]
    pub fn rules(&self) -> Vec<Rule> {
        let mut count = 0;
        // SAFETY: the handle is live and the out pointer is a valid local.
        let status = unsafe { rustleaks_engine_rule_count(self.0.as_ptr(), &raw mut count) };
        assert_eq!(status, STATUS_OK);
        (0..count)
            .map(|index| {
                let mut view = RuleView {
                    id: Bytes::EMPTY,
                    description: Bytes::EMPTY,
                    tags: ptr::null(),
                    tag_count: 0,
                    keywords: ptr::null(),
                    keyword_count: 0,
                };
                // SAFETY: the handle is live and the view is a valid local;
                // its contents belong to the live engine while copied.
                unsafe {
                    assert_eq!(
                        rustleaks_engine_rule(self.0.as_ptr(), index, &raw mut view),
                        STATUS_OK
                    );
                    Rule {
                        id: copy(view.id),
                        description: copy(view.description),
                        tags: copy_list(view.tags, view.tag_count),
                        keywords: copy_list(view.keywords, view.keyword_count),
                    }
                }
            })
            .collect()
    }

    /// Scans `input` with optional arguments and cancel handle.
    ///
    /// # Errors
    ///
    /// Returns the library error.
    pub fn scan(
        &self,
        input: &[u8],
        scan: Option<&Scan<'_>>,
        cancel: Option<&Cancel>,
    ) -> Result<Outcome, Error> {
        // An empty slice may have a dangling pointer; pass null, as a
        // wrapper with an empty buffer can.
        let pointer = if input.is_empty() {
            ptr::null()
        } else {
            input.as_ptr()
        };
        let args = scan.map(Scan::raw);
        // SAFETY: the pointer is null with length 0 or a valid slice, and
        // the path in `args` borrows `scan`, which outlives the call.
        unsafe { self.scan_raw(pointer, input.len(), args.as_ref(), cancel) }
    }

    /// Scans with a raw input pointer.
    ///
    /// # Errors
    ///
    /// Returns the library error.
    ///
    /// # Safety
    ///
    /// `input` must follow the byte pointer rule for `len`, and the path in
    /// `args` must too.
    pub unsafe fn scan_raw(
        &self,
        input: *const u8,
        len: usize,
        args: Option<&ScanArgs>,
        cancel: Option<&Cancel>,
    ) -> Result<Outcome, Error> {
        let mut result = ptr::null_mut();
        let mut error = ptr::null_mut();
        let args = args.map_or(ptr::null(), ptr::from_ref);
        let cancel = cancel.map_or(ptr::null(), |cancel| cancel.0.cast_const());
        // SAFETY: the engine and cancel handles are live; the caller
        // guarantees the input and path; the out pointers are valid locals.
        let status = unsafe {
            rustleaks_scan(
                self.0.as_ptr(),
                input,
                len,
                args,
                cancel,
                &raw mut result,
                &raw mut error,
            )
        };
        if status != STATUS_OK {
            assert!(result.is_null());
            // SAFETY: on failure `error` is null or a new error handle.
            return Err(unsafe { Error::take(status, error) });
        }
        assert!(error.is_null());
        // SAFETY: `result` is a new result handle that this call owns.
        Ok(unsafe { take_result(result) })
    }
}

/// Copies a result handle and frees it.
///
/// # Safety
///
/// `result` must be a live result handle that no one else uses.
unsafe fn take_result(result: *mut ResultHandle) -> Outcome {
    let mut status = StatusView::default();
    let mut count = 0;
    // SAFETY: the handle is live and the out pointers are valid locals.
    unsafe {
        assert_eq!(rustleaks_result_status(result, &raw mut status), STATUS_OK);
        assert_eq!(rustleaks_result_count(result, &raw mut count), STATUS_OK);
    }
    let findings = (0..count)
        .map(|index| {
            let mut view = empty_finding_view();
            // SAFETY: the handle is live and the view is a valid local; its
            // contents belong to the live result while copied.
            unsafe {
                assert_eq!(
                    rustleaks_result_finding(result, index, &raw mut view),
                    STATUS_OK
                );
                finding(&view)
            }
        })
        .collect();
    // SAFETY: the handle is freed once, after its last use.
    assert_eq!(unsafe { rustleaks_result_free(result) }, STATUS_OK);
    Outcome { status, findings }
}

/// A finding view with no contents.
#[must_use]
pub const fn empty_finding_view() -> FindingView {
    FindingView {
        rule_id: Bytes::EMPTY,
        description: Bytes::EMPTY,
        tags: ptr::null(),
        tag_count: 0,
        secret: Bytes::EMPTY,
        match_text: Bytes::EMPTY,
        line: Bytes::EMPTY,
        path: Bytes::EMPTY,
        start_line: 0,
        end_line: 0,
        start_column: 0,
        end_column: 0,
        secret_start: 0,
        secret_end: 0,
        match_start: 0,
        match_end: 0,
        entropy: 0.0,
        secret_range_exact: 0,
        match_range_exact: 0,
    }
}

/// Copies a finding view.
///
/// # Safety
///
/// The view must come from a live result.
unsafe fn finding(view: &FindingView) -> Finding {
    let range = |exact: u8, start, end| (exact == 1).then_some((start, end));
    // SAFETY: the views belong to the live result, as the caller guarantees.
    unsafe {
        Finding {
            rule_id: copy(view.rule_id),
            description: copy(view.description),
            tags: copy_list(view.tags, view.tag_count),
            secret: copy(view.secret),
            match_text: copy(view.match_text),
            line: copy(view.line),
            path: copy(view.path),
            start_line: view.start_line,
            end_line: view.end_line,
            start_column: view.start_column,
            end_column: view.end_column,
            secret_range: range(view.secret_range_exact, view.secret_start, view.secret_end),
            match_range: range(view.match_range_exact, view.match_start, view.match_end),
            entropy: view.entropy,
            line_view: (view.line.ptr.addr(), view.line.len),
        }
    }
}

/// Scan arguments in safe Rust: the fields of [`ScanArgs`], with the path as
/// a borrowed slice. [`Scan::raw`] builds the C struct for one call.
#[derive(Clone, Copy, Debug)]
pub struct Scan<'a> {
    /// Path bytes, or empty.
    pub path: &'a [u8],
    /// `SCAN_SET_*` bits.
    pub overrides: u64,
    /// Decode depth.
    pub decode_depth: u64,
    /// `BASE64_*` value.
    pub base64_mode: u64,
    /// Redaction percent.
    pub redaction_percent: u64,
    /// Decoded byte budget.
    pub max_decoded_bytes: u64,
    /// Work unit budget.
    pub max_work_units: u64,
    /// Finding record budget.
    pub max_finding_records: u64,
    /// Finding payload byte budget.
    pub max_finding_payload_bytes: u64,
    /// Collected span budget.
    pub max_collected_spans: u64,
    /// Normalization byte budget.
    pub max_normalization_bytes: u64,
    /// Nanoseconds until the deadline.
    pub deadline_ns: u64,
    /// Raw allow comment byte, which the library checks.
    pub allow_comments: u8,
}

impl Scan<'_> {
    /// The C struct. Its path pointer borrows `self.path`, so it is valid
    /// while `self` is.
    #[must_use]
    pub fn raw(&self) -> ScanArgs {
        ScanArgs {
            path: if self.path.is_empty() {
                ptr::null()
            } else {
                self.path.as_ptr()
            },
            path_len: self.path.len(),
            overrides: self.overrides,
            decode_depth: self.decode_depth,
            base64_mode: self.base64_mode,
            redaction_percent: self.redaction_percent,
            max_decoded_bytes: self.max_decoded_bytes,
            max_work_units: self.max_work_units,
            max_finding_records: self.max_finding_records,
            max_finding_payload_bytes: self.max_finding_payload_bytes,
            max_collected_spans: self.max_collected_spans,
            max_normalization_bytes: self.max_normalization_bytes,
            deadline_ns: self.deadline_ns,
            allow_comments: self.allow_comments,
        }
    }
}

/// Scan arguments with no overrides and the given path.
#[must_use]
pub const fn scan_args(path: &[u8]) -> Scan<'_> {
    Scan {
        path,
        overrides: 0,
        decode_depth: 0,
        base64_mode: 0,
        redaction_percent: 0,
        max_decoded_bytes: 0,
        max_work_units: 0,
        max_finding_records: 0,
        max_finding_payload_bytes: 0,
        max_collected_spans: 0,
        max_normalization_bytes: 0,
        deadline_ns: 0,
        allow_comments: 0,
    }
}

/// Reads fuzz input in small pieces. Missing bytes read as zero.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> u8 {
        let (first, rest) = self.0.split_first().map_or((0, &[][..]), |(f, r)| (*f, r));
        self.0 = rest;
        first
    }

    fn u64(&mut self) -> u64 {
        let mut value = 0_u64;
        for _ in 0..8 {
            value = (value << 8) | u64::from(self.byte());
        }
        value
    }

    fn take(&mut self, len: usize) -> &'a [u8] {
        let (taken, rest) = self.0.split_at(len.min(self.0.len()));
        self.0 = rest;
        taken
    }

    fn rest(&mut self) -> &'a [u8] {
        self.take(self.0.len())
    }
}

/// Drives the exports with valid pointers and arbitrary bytes, lengths,
/// keys and values, and checks the results that hold for every input.
///
/// The input holds a configuration, option calls, rule IDs, scan arguments
/// and the scanned bytes. It never loads the built-in rules, so one run
/// stays short.
///
/// # Panics
///
/// Panics when a library call breaks the ABI contract.
pub fn exercise(data: &[u8]) {
    let mut reader = Reader(data);
    let Ok(mut options) = Options::new() else {
        panic!("options_new failed with the library ABI number");
    };
    let config_len = usize::from(u16::from_be_bytes([reader.byte(), reader.byte()]));
    let config = reader.take(config_len);
    assert!(options.set_config(config).is_ok());
    // Few threads by default, so that runs stay short; the options below can
    // still turn the scan threads on.
    assert!(
        options
            .set_bool(crate::abi::OPTION_SCAN_ON_CALLER_THREAD, 1)
            .is_ok()
    );
    assert!(options.set_u64(crate::abi::OPTION_WORKERS, 1).is_ok());
    let mut redacted = false;
    let mut max_input = crate::handles::DEFAULT_MAX_INPUT_BYTES;
    for _ in 0..usize::from(reader.byte() % 8) {
        let kind = reader.byte();
        let key = u32::from(reader.byte() % 14);
        let mut value = match reader.byte() % 4 {
            0 => u64::from(reader.byte()),
            1 => u64::MAX,
            _ => reader.u64() % 100_000,
        };
        if key == crate::abi::OPTION_WORKERS && value <= crate::abi::MAX_WORKERS {
            // Accepted worker counts start that many threads; keep it small.
            value %= 3;
        }
        let status = match kind % 3 {
            0 => {
                let status = options.set_u64(key, value);
                if status.is_ok() {
                    redacted |= key == crate::abi::OPTION_REDACTION_PERCENT && value != 0;
                    if key == crate::abi::OPTION_MAX_INPUT_BYTES {
                        max_input = value;
                    }
                }
                status
            }
            1 => options.set_bool(key, reader.byte() % 3),
            _ => {
                let len = usize::from(reader.byte() % 32);
                options.add_rule_id(reader.take(len))
            }
        };
        if let Err(error) = status {
            assert_eq!(error.kind, ERROR_INVALID_ARGUMENT);
        }
    }
    let engine = match Engine::new(&options) {
        Ok(engine) => engine,
        Err(error) => {
            assert!(
                [ERROR_CONFIG, ERROR_RULE_SELECTION, ERROR_ENGINE].contains(&error.kind),
                "unexpected engine error {}",
                error.kind
            );
            assert!(!error.message.is_empty());
            return;
        }
    };
    drop(options);
    let _ = engine.rules();
    assert_eq!(engine.max_input_bytes(), max_input);
    let path_len = usize::from(reader.byte() % 64);
    let path = reader.take(path_len);
    let mut args = scan_args(path);
    args.overrides = reader.u64() & 0xfff;
    args.decode_depth = u64::from(reader.byte() % 4);
    args.base64_mode = u64::from(reader.byte() % 3);
    args.redaction_percent = u64::from(reader.byte());
    args.allow_comments = reader.byte() % 3;
    args.max_decoded_bytes = u64::from(reader.byte()) * 64;
    args.max_work_units = u64::from(reader.byte()) * 64;
    args.max_finding_records = u64::from(reader.byte());
    args.max_finding_payload_bytes = u64::from(reader.byte()) * 64;
    args.max_collected_spans = u64::from(reader.byte());
    args.max_normalization_bytes = u64::from(reader.byte()) * 64;
    args.deadline_ns = u64::from(reader.byte()) * 1_000_000;
    let input = reader.rest();
    match engine.scan(input, Some(&args), None) {
        Ok(outcome) => check_outcome(input, path, redacted, &args, &outcome),
        Err(error) if error.kind == ERROR_INPUT_TOO_LARGE => {
            assert!(max_input != crate::abi::UNLIMITED);
            assert!(u64::try_from(input.len()).unwrap_or(u64::MAX) > max_input);
        }
        Err(error) => assert_eq!(error.kind, ERROR_INVALID_ARGUMENT, "{}", error.message),
    }
}

fn check_outcome(input: &[u8], path: &[u8], redacted: bool, args: &Scan<'_>, outcome: &Outcome) {
    use crate::abi::{SCAN_SET_REDACTION_PERCENT, TERMINATION_COMPLETE, TERMINATION_OTHER};
    assert!((TERMINATION_COMPLETE..=TERMINATION_OTHER).contains(&outcome.status.termination));
    let unredacted = if args.overrides & SCAN_SET_REDACTION_PERCENT == 0 {
        !redacted
    } else {
        args.redaction_percent == 0
    };
    let length = u64::try_from(input.len()).unwrap_or(u64::MAX);
    for finding in &outcome.findings {
        assert_eq!(finding.path, path);
        assert!(finding.start_line <= finding.end_line);
        for (start, end) in [finding.secret_range, finding.match_range]
            .into_iter()
            .flatten()
        {
            assert!(start <= end && end <= length);
        }
        if unredacted && let Some((start, end)) = finding.match_range {
            let (start, end) = (
                usize::try_from(start).unwrap_or(usize::MAX),
                usize::try_from(end).unwrap_or(usize::MAX),
            );
            assert_eq!(finding.match_text, input[start..end]);
        }
    }
}
