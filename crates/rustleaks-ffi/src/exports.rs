//! The exported C functions.
//!
//! Every function returns a status: `STATUS_OK` or an `ERROR_*` kind. Every
//! body runs inside `catch_unwind`, so a panic returns `ERROR_PANIC` instead
//! of aborting the host process. A function that returns a handle writes
//! null to its out parameter first and the handle only on success.
//!
//! Pointer rules for every function:
//!
//! - A handle pointer is null or a live handle of the named type that this
//!   library returned and that has not been freed.
//! - A byte pointer with a length of 0 can be null. Otherwise it points to
//!   that many readable bytes that do not change during the call.
//! - An out pointer is null or valid and aligned for one write of its type.
//!   A null out pointer gives `ERROR_INVALID_ARGUMENT`.
//!
//! The library checks for null and misaligned pointers. It cannot check the
//! other rules.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use crate::abi::{
    ABI_VERSION, Bytes, ERROR_ABI_MISMATCH, ERROR_INVALID_ARGUMENT, ERROR_PANIC, FindingView,
    RuleView, SCAN_SET_ALL, STATUS_OK, ScanArgs, StatusView,
};
use crate::cancel::CancelHandle;
use crate::handles::{EngineHandle, FfiError, Options, ResultHandle, ScanRequest};

/// The library version, the same as the `rustleaks-core` version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runs `body` and turns a panic into `ERROR_PANIC`.
fn guarded(body: impl FnOnce() -> Result<(), i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(status)) => status,
        Err(_) => ERROR_PANIC,
    }
}

/// Runs `body` and returns its error, or the error for a panic, through
/// `error`, which the caller has checked and set to null.
///
/// # Safety
///
/// `error` must be valid and aligned for one write.
unsafe fn guarded_with_error(
    error: *mut *mut FfiError,
    body: impl FnOnce() -> Result<(), FfiError>,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| Err(FfiError::panic()));
    match outcome {
        Ok(()) => STATUS_OK,
        Err(failure) => {
            let kind = failure.kind();
            // SAFETY: the caller guarantees that `error` is valid for a write.
            unsafe { error.write(Box::into_raw(Box::new(failure))) };
            kind
        }
    }
}

/// Writes `value` through `out`.
///
/// # Safety
///
/// `out` must be null or valid for one write of `T`.
unsafe fn write_out<T>(out: *mut T, value: T) -> Result<(), i32> {
    if out.is_null() || !out.is_aligned() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    // SAFETY: `out` is not null, is aligned, and the caller guarantees that
    // it is valid for a write.
    unsafe { out.write(value) };
    Ok(())
}

/// Checks a handle out parameter and sets it to null.
///
/// # Safety
///
/// `out` must be null or valid for one write of a pointer.
unsafe fn clear_out<T>(out: *mut *mut T) -> Result<(), i32> {
    // SAFETY: forwarded from the caller.
    unsafe { write_out(out, ptr::null_mut()) }
}

/// Borrows a handle.
///
/// # Safety
///
/// `handle` must be null or a live handle of type `T` from this library,
/// not freed and not borrowed mutably during `'a`.
unsafe fn borrow<'a, T>(handle: *const T) -> Result<&'a T, i32> {
    if handle.is_null() || !handle.is_aligned() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    // SAFETY: the pointer is not null and aligned, and the caller guarantees
    // that it is a live handle with no mutable borrow.
    Ok(unsafe { &*handle })
}

/// Borrows a handle mutably.
///
/// # Safety
///
/// `handle` must be null or a live handle of type `T` from this library,
/// not freed and not used by anyone else during `'a`.
unsafe fn borrow_mut<'a, T>(handle: *mut T) -> Result<&'a mut T, i32> {
    if handle.is_null() || !handle.is_aligned() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    // SAFETY: the pointer is not null and aligned, and the caller guarantees
    // exclusive access to a live handle.
    Ok(unsafe { &mut *handle })
}

/// Borrows `len` bytes at `bytes`. A length of 0 never reads the pointer.
///
/// # Safety
///
/// When `len` is not 0, `bytes` must be null or point to `len` readable
/// bytes that do not change during `'a`.
unsafe fn borrow_bytes<'a>(bytes: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if bytes.is_null() || isize::try_from(len).is_err() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    // SAFETY: `bytes` is not null, `u8` needs no alignment, `len` fits in
    // `isize`, and the caller guarantees `len` readable, unchanging bytes.
    Ok(unsafe { std::slice::from_raw_parts(bytes, len) })
}

/// Frees a handle made with `Box::into_raw`. Null is accepted.
///
/// # Safety
///
/// `handle` must be null or a live handle of type `T` from this library
/// that no one uses during or after the call.
unsafe fn free<T>(handle: *mut T) -> Result<(), i32> {
    if handle.is_null() {
        return Ok(());
    }
    if !handle.is_aligned() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    // SAFETY: the caller guarantees that `handle` came from `Box::into_raw`
    // in this library and is not used again.
    drop(unsafe { Box::from_raw(handle) });
    Ok(())
}

/// Writes the ABI number to `out`.
///
/// # Safety
///
/// `out` must be null or valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_abi_version(out: *mut u32) -> i32 {
    // SAFETY: forwarded from the caller.
    guarded(|| unsafe { write_out(out, ABI_VERSION) })
}

/// Writes the library version, such as `0.2.0`, as bytes that live as long
/// as the library.
///
/// # Safety
///
/// `out_ptr` and `out_len` must be null or valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_version(out_ptr: *mut *const u8, out_len: *mut usize) -> i32 {
    guarded(|| {
        if out_ptr.is_null() || out_len.is_null() {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        // SAFETY: forwarded from the caller.
        unsafe {
            write_out(out_ptr, VERSION.as_ptr())?;
            write_out(out_len, VERSION.len())
        }
    })
}

/// Creates an options handle with the defaults. Fails with
/// `ERROR_ABI_MISMATCH` unless `abi_version` is the library's ABI number.
///
/// # Safety
///
/// `out` must be null or valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_options_new(abi_version: u32, out: *mut *mut Options) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe { clear_out(out)? };
        if abi_version != ABI_VERSION {
            return Err(ERROR_ABI_MISMATCH);
        }
        let handle = Box::into_raw(Box::new(Options::default()));
        // SAFETY: `out` was checked by `clear_out`.
        unsafe { out.write(handle) };
        Ok(())
    })
}

/// Replaces the built-in rules with a TOML configuration. The bytes are
/// copied. `[extend] useDefault = true` adds the built-in rules again. A
/// configuration with no rules, including an empty one, builds an engine
/// that reports nothing.
///
/// # Safety
///
/// `options` must be null or a live options handle that no other thread
/// uses during the call. `config` follows the byte pointer rule.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_options_set_config(
    options: *mut Options,
    config: *const u8,
    config_len: usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        let (options, config) =
            unsafe { (borrow_mut(options)?, borrow_bytes(config, config_len)?) };
        options.set_config(config);
        Ok(())
    })
}

/// Adds a rule ID to the selection. The bytes are copied.
///
/// # Safety
///
/// `options` must be null or a live options handle that no other thread
/// uses during the call. `id` follows the byte pointer rule.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_options_add_rule_id(
    options: *mut Options,
    id: *const u8,
    id_len: usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        let (options, id) = unsafe { (borrow_mut(options)?, borrow_bytes(id, id_len)?) };
        options.add_rule_id(id)
    })
}

/// Sets the numeric option `key` (`OPTION_*`).
///
/// # Safety
///
/// `options` must be null or a live options handle that no other thread
/// uses during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_options_set_u64(
    options: *mut Options,
    key: u32,
    value: u64,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        let options = unsafe { borrow_mut(options)? };
        options.set_u64(key, value)
    })
}

/// Sets the boolean option `key` (`OPTION_*`). `value` is 0 or 1.
///
/// # Safety
///
/// `options` must be null or a live options handle that no other thread
/// uses during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_options_set_bool(
    options: *mut Options,
    key: u32,
    value: u8,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        let options = unsafe { borrow_mut(options)? };
        let value = match value {
            0 => false,
            1 => true,
            _ => return Err(ERROR_INVALID_ARGUMENT),
        };
        options.set_bool(key, value)
    })
}

/// Frees an options handle. Null is accepted.
///
/// # Safety
///
/// `options` must be null or a live options handle that no one uses during
/// or after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_options_free(options: *mut Options) -> i32 {
    // SAFETY: forwarded from the caller.
    guarded(|| unsafe { free(options) })
}

/// Builds an engine from the options on a new thread with an 8 MiB stack,
/// and starts its scan threads unless `OPTION_SCAN_ON_CALLER_THREAD` is set.
/// The options handle can be freed or changed afterwards without changing
/// the engine.
///
/// # Safety
///
/// `options` must be null or a live options handle that no other thread
/// changes during the call. `out` and `error` must be null or valid for one
/// write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_new(
    options: *const Options,
    out: *mut *mut EngineHandle,
    error: *mut *mut FfiError,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            clear_out(error)?;
            clear_out(out)?;
        }
        // SAFETY: `error` was checked by `clear_out`; the other pointers are
        // forwarded from the caller.
        let status = unsafe {
            guarded_with_error(error, || {
                let options = borrow(options).map_err(|status| {
                    FfiError::new(status, "the options handle is null or misaligned")
                })?;
                let engine = EngineHandle::build(options)?;
                out.write(Box::into_raw(Box::new(engine)));
                Ok(())
            })
        };
        if status == STATUS_OK {
            Ok(())
        } else {
            Err(status)
        }
    })
}

/// Frees an engine and joins its scan threads. Null is accepted. No scan may
/// use the engine during or after the call.
///
/// # Safety
///
/// `engine` must be null or a live engine handle that no one uses during or
/// after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_free(engine: *mut EngineHandle) -> i32 {
    // SAFETY: forwarded from the caller.
    guarded(|| unsafe { free(engine) })
}

/// Writes the number of workers that share the engine's search caches.
/// Wrappers run at most this many scans at once.
///
/// # Safety
///
/// `engine` must be null or a live engine handle. `out` must be null or
/// valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_workers(
    engine: *const EngineHandle,
    out: *mut usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let engine = borrow(engine)?;
            write_out(out, engine.workers())
        }
    })
}

/// Writes the engine's inclusive input limit in bytes, or `UNLIMITED`.
/// Wrappers check an input against it before they copy or pass it.
///
/// # Safety
///
/// `engine` must be null or a live engine handle. `out` must be null or
/// valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_max_input_bytes(
    engine: *const EngineHandle,
    out: *mut u64,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let engine = borrow(engine)?;
            write_out(out, engine.max_input_bytes())
        }
    })
}

/// Writes the number of rules that can report findings.
///
/// # Safety
///
/// `engine` must be null or a live engine handle. `out` must be null or
/// valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_rule_count(
    engine: *const EngineHandle,
    out: *mut usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let engine = borrow(engine)?;
            write_out(out, engine.rule_count())
        }
    })
}

/// Writes the view of rule `index`, in report order. The view points into
/// the engine and is valid until the engine is freed.
///
/// # Safety
///
/// `engine` must be null or a live engine handle. `out` must be null or
/// valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_rule(
    engine: *const EngineHandle,
    index: usize,
    out: *mut RuleView,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let engine = borrow(engine)?;
            let view = engine.rule(index).ok_or(ERROR_INVALID_ARGUMENT)?;
            write_out(out, view)
        }
    })
}

/// Creates a cancel handle. One handle can serve many scans.
///
/// # Safety
///
/// `out` must be null or valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_cancel_new(out: *mut *mut CancelHandle) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            clear_out(out)?;
            out.write(Box::into_raw(Box::default()));
        }
        Ok(())
    })
}

/// Sets a cancel handle. Scans that use it stop at their next check. Any
/// thread can call this while scans run.
///
/// # Safety
///
/// `cancel` must be null or a live cancel handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_cancel_set(cancel: *const CancelHandle) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe { borrow(cancel)? }.set();
        Ok(())
    })
}

/// Frees a cancel handle. Null is accepted.
///
/// # Safety
///
/// `cancel` must be null or a live cancel handle that no scan uses during
/// or after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_cancel_free(cancel: *mut CancelHandle) -> i32 {
    // SAFETY: forwarded from the caller.
    guarded(|| unsafe { free(cancel) })
}

/// Checks and copies scan arguments.
///
/// # Safety
///
/// `args` must be null or point to one readable `ScanArgs` whose `path`
/// follows the byte pointer rule during `'a`.
unsafe fn scan_request<'a>(args: *const ScanArgs) -> Result<ScanRequest<'a>, FfiError> {
    let invalid = |message: &str| FfiError::new(ERROR_INVALID_ARGUMENT, message);
    if args.is_null() {
        return Ok(ScanRequest::default());
    }
    if !args.is_aligned() {
        return Err(invalid("the scan arguments are misaligned"));
    }
    // SAFETY: `args` is not null and aligned, and the caller guarantees one
    // readable value. Reading copies it, so later changes do not matter.
    let args = unsafe { args.read() };
    // SAFETY: the caller guarantees the path pointer rule.
    let path = unsafe { borrow_bytes(args.path, args.path_len) }
        .map_err(|_| invalid("the scan path pointer is null"))?;
    if args.overrides & !SCAN_SET_ALL != 0 {
        return Err(invalid("unknown bits in the scan argument overrides"));
    }
    let allow_comments = match args.allow_comments {
        0 => false,
        1 => true,
        _ => {
            return Err(invalid(
                "allow_comments in the scan arguments is not 0 or 1",
            ));
        }
    };
    Ok(ScanRequest {
        path,
        overrides: args.overrides,
        decode_depth: args.decode_depth,
        base64_mode: args.base64_mode,
        redaction_percent: args.redaction_percent,
        allow_comments,
        max_decoded_bytes: args.max_decoded_bytes,
        max_work_units: args.max_work_units,
        max_finding_records: args.max_finding_records,
        max_finding_payload_bytes: args.max_finding_payload_bytes,
        max_collected_spans: args.max_collected_spans,
        max_normalization_bytes: args.max_normalization_bytes,
        deadline_ns: args.deadline_ns,
    })
}

/// Scans `input` with the engine. Many threads can scan with one engine at
/// once. The input and the path are copied before the scan starts, and no
/// pointer argument is used after the call returns. The scan runs on one of
/// the engine's scan threads while the caller waits, or on the calling
/// thread when `OPTION_SCAN_ON_CALLER_THREAD` is set.
///
/// A scan that stops early still returns `STATUS_OK` and a result; read its
/// status with `rustleaks_result_status`.
///
/// # Safety
///
/// `engine` must be null or a live engine handle, and `cancel` null or a
/// live cancel handle; neither may be freed during the call. `input`
/// follows the byte pointer rule. `args` must be null or point to one
/// readable `ScanArgs`, whose `path` follows the byte pointer rule. `out`
/// and `error` must be null or valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_scan(
    engine: *const EngineHandle,
    input: *const u8,
    input_len: usize,
    args: *const ScanArgs,
    cancel: *const CancelHandle,
    out: *mut *mut ResultHandle,
    error: *mut *mut FfiError,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            clear_out(error)?;
            clear_out(out)?;
        }
        // SAFETY: `error` was checked by `clear_out`; the other pointers are
        // forwarded from the caller.
        let status = unsafe {
            guarded_with_error(error, || {
                let invalid = |message: &str| FfiError::new(ERROR_INVALID_ARGUMENT, message);
                let engine = borrow(engine)
                    .map_err(|_| invalid("the engine handle is null or misaligned"))?;
                let cancel = if cancel.is_null() {
                    None
                } else {
                    let handle =
                        borrow(cancel).map_err(|_| invalid("the cancel handle is misaligned"))?;
                    Some(handle.flag())
                };
                let request = scan_request(args)?;
                // Check the length before touching the input.
                engine.check_input_size(input_len)?;
                let input = borrow_bytes(input, input_len)
                    .map_err(|_| invalid("the input pointer is null"))?;
                let result = engine.scan(input, &request, cancel)?;
                out.write(Box::into_raw(Box::new(result)));
                Ok(())
            })
        };
        if status == STATUS_OK {
            Ok(())
        } else {
            Err(status)
        }
    })
}

/// Writes how the scan ended and what it used.
///
/// # Safety
///
/// `result` must be null or a live result handle. `out` must be null or
/// valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_result_status(
    result: *const ResultHandle,
    out: *mut StatusView,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let result = borrow(result)?;
            write_out(out, result.status())
        }
    })
}

/// Writes the number of findings.
///
/// # Safety
///
/// `result` must be null or a live result handle. `out` must be null or
/// valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_result_count(
    result: *const ResultHandle,
    out: *mut usize,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let result = borrow(result)?;
            write_out(out, result.count())
        }
    })
}

/// Writes the view of finding `index`. The view points into the result and
/// is valid until the result is freed.
///
/// # Safety
///
/// `result` must be null or a live result handle. `out` must be null or
/// valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_result_finding(
    result: *const ResultHandle,
    index: usize,
    out: *mut FindingView,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let result = borrow(result)?;
            let view = result.finding(index).ok_or(ERROR_INVALID_ARGUMENT)?;
            write_out(out, view)
        }
    })
}

/// Frees a result. Null is accepted.
///
/// # Safety
///
/// `result` must be null or a live result handle that no one uses during or
/// after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_result_free(result: *mut ResultHandle) -> i32 {
    // SAFETY: forwarded from the caller.
    guarded(|| unsafe { free(result) })
}

/// Writes the `ERROR_*` kind of an error.
///
/// # Safety
///
/// `error` must be null or a live error handle. `out` must be null or valid
/// for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_error_kind(error: *const FfiError, out: *mut i32) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller.
        unsafe {
            let error = borrow(error)?;
            write_out(out, error.kind())
        }
    })
}

/// Writes the UTF-8 message of an error. It points into the error and is
/// valid until the error is freed. A configuration message can quote
/// configuration text. No message quotes scanned bytes.
///
/// # Safety
///
/// `error` must be null or a live error handle. `out_ptr` and `out_len`
/// must be null or valid for one write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_error_message(
    error: *const FfiError,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    guarded(|| {
        if out_ptr.is_null() || out_len.is_null() {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        // SAFETY: forwarded from the caller.
        unsafe {
            let error = borrow(error)?;
            let message = Bytes::of(error.message().as_bytes());
            write_out(out_ptr, message.ptr)?;
            write_out(out_len, message.len)
        }
    })
}

/// Frees an error. Null is accepted.
///
/// # Safety
///
/// `error` must be null or a live error handle that no one uses during or
/// after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_error_free(error: *mut FfiError) -> i32 {
    // SAFETY: forwarded from the caller.
    guarded(|| unsafe { free(error) })
}
