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
//!   A null out pointer gives `ERROR_INVALID_ARGUMENT`, except the error out
//!   pointer of `rustleaks_engine_new` and `rustleaks_scan`: null there means
//!   that the caller wants only the status. Every out pointer is checked
//!   once, by `Out::new`, and then written only through that `Out`.
//!
//! The library checks for null and misaligned pointers. It cannot check the
//! other rules.

use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};

use crate::abi::{
    ABI_VERSION, Bytes, ERROR_ABI_MISMATCH, ERROR_CLOSED, ERROR_INVALID_ARGUMENT, ERROR_PANIC,
    FindingView, RuleView, SCAN_SET_ALL, STATUS_OK, ScanArgs, StatusView,
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

/// A checked out parameter: a pointer that is not null, is aligned, and that
/// the caller of the export promised is valid for writes of `T` during the
/// call. It can only be made through the unsafe [`Out::new`], so every write
/// through it relies on that one check and that one promise.
struct Out<'a, T> {
    target: NonNull<T>,
    call: PhantomData<&'a mut T>,
}

impl<T> Out<'_, T> {
    /// Checks `pointer` and keeps it for writes during the call.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INVALID_ARGUMENT` for a null or misaligned pointer.
    ///
    /// # Safety
    ///
    /// `pointer` must be null or valid for writes of `T` until the export
    /// returns, and nothing else may access it meanwhile.
    unsafe fn new(pointer: *mut T) -> Result<Self, i32> {
        let target = NonNull::new(pointer).ok_or(ERROR_INVALID_ARGUMENT)?;
        if !pointer.is_aligned() {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        Ok(Self {
            target,
            call: PhantomData,
        })
    }

    /// Like [`Out::new`], but a null pointer means that the caller does not
    /// want the value.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_INVALID_ARGUMENT` for a misaligned pointer.
    ///
    /// # Safety
    ///
    /// As for [`Out::new`].
    unsafe fn optional(pointer: *mut T) -> Result<Option<Self>, i32> {
        if pointer.is_null() {
            return Ok(None);
        }
        // SAFETY: forwarded from the caller.
        unsafe { Self::new(pointer) }.map(Some)
    }

    /// Writes `value`, without reading or dropping the old contents.
    fn write(&mut self, value: T) {
        // SAFETY: `Out::new` checked that the pointer is not null and is
        // aligned, and its caller promised that it is valid for writes with
        // no other access until the export returns, which `'_` bounds.
        unsafe { self.target.as_ptr().write(value) };
    }
}

/// Checks a handle out parameter and sets it to null, so that it is null
/// unless the export later writes a handle.
///
/// # Errors
///
/// Returns `ERROR_INVALID_ARGUMENT` for a null or misaligned pointer.
///
/// # Safety
///
/// As for [`Out::new`].
unsafe fn handle_out<'a, T>(pointer: *mut *mut T) -> Result<Out<'a, *mut T>, i32> {
    // SAFETY: forwarded from the caller.
    let mut out = unsafe { Out::new(pointer) }?;
    out.write(ptr::null_mut());
    Ok(out)
}

/// Checks an optional error out parameter and sets it to null.
///
/// # Errors
///
/// Returns `ERROR_INVALID_ARGUMENT` for a misaligned pointer.
///
/// # Safety
///
/// As for [`Out::new`].
unsafe fn error_out<'a>(
    pointer: *mut *mut FfiError,
) -> Result<Option<Out<'a, *mut FfiError>>, i32> {
    // SAFETY: forwarded from the caller.
    let mut out = unsafe { Out::optional(pointer) }?;
    if let Some(out) = out.as_mut() {
        out.write(ptr::null_mut());
    }
    Ok(out)
}

/// Writes one value through a checked out parameter.
///
/// # Errors
///
/// Returns `ERROR_INVALID_ARGUMENT` for a null or misaligned pointer.
///
/// # Safety
///
/// As for [`Out::new`].
unsafe fn write_out<T>(pointer: *mut T, value: T) -> Result<(), i32> {
    // SAFETY: forwarded from the caller.
    unsafe { Out::new(pointer) }?.write(value);
    Ok(())
}

/// Runs `body` and returns its error, or the error for a panic, as a new
/// error handle through `error` when the caller asked for one. Without an
/// error out parameter the error is dropped and only its kind is returned.
fn guarded_with_error(
    error: Option<&mut Out<'_, *mut FfiError>>,
    body: impl FnOnce() -> Result<(), FfiError>,
) -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| Err(FfiError::panic()));
    match outcome {
        Ok(()) => STATUS_OK,
        Err(failure) => {
            let kind = failure.kind();
            if let Some(error) = error {
                error.write(Box::into_raw(Box::new(failure)));
            }
            kind
        }
    }
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

/// Borrows an engine handle and checks that this process made it.
///
/// # Errors
///
/// Returns `ERROR_INVALID_ARGUMENT` for a null or misaligned handle and
/// `ERROR_CLOSED` for an engine made in another process, such as the parent
/// of a forked child.
///
/// # Safety
///
/// As for [`borrow`].
unsafe fn borrow_engine<'a>(engine: *const EngineHandle) -> Result<&'a EngineHandle, i32> {
    // SAFETY: forwarded from the caller.
    let engine = unsafe { borrow(engine) }?;
    if engine.in_owner_process() {
        Ok(engine)
    } else {
        Err(ERROR_CLOSED)
    }
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
        // SAFETY: forwarded from the caller. Both pointers are checked
        // before either is written.
        let (mut ptr_out, mut len_out) = unsafe { (Out::new(out_ptr)?, Out::new(out_len)?) };
        ptr_out.write(VERSION.as_ptr());
        len_out.write(VERSION.len());
        Ok(())
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
        let mut out = unsafe { handle_out(out) }?;
        if abi_version != ABI_VERSION {
            return Err(ERROR_ABI_MISMATCH);
        }
        out.write(Box::into_raw(Box::new(Options::default())));
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
/// write. A null `error` means that the caller wants only the status.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_new(
    options: *const Options,
    out: *mut *mut EngineHandle,
    error: *mut *mut FfiError,
) -> i32 {
    guarded(|| {
        // SAFETY: forwarded from the caller. Both pointers are checked and
        // set to null before either error returns, so a valid `out` is null
        // even when `error` is misaligned.
        let (out, error) = unsafe { (handle_out(out), error_out(error)) };
        let (mut error, mut out) = (error?, out?);
        let status = guarded_with_error(error.as_mut(), || {
            // SAFETY: forwarded from the caller.
            let options = unsafe { borrow(options) }.map_err(|status| {
                FfiError::new(status, "the options handle is null or misaligned")
            })?;
            let engine = EngineHandle::build(options)?;
            out.write(Box::into_raw(Box::new(engine)));
            Ok(())
        });
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
/// In a process other than the one that made the engine, such as a forked
/// child, this releases nothing and returns `STATUS_OK`. The child has none
/// of the scan threads, so dropping the engine there could wait forever or
/// crash; the handle's memory is left as the fork copied it.
///
/// # Safety
///
/// `engine` must be null or a live engine handle that no one uses during or
/// after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rustleaks_engine_free(engine: *mut EngineHandle) -> i32 {
    guarded(|| {
        if engine.is_null() {
            return Ok(());
        }
        // SAFETY: forwarded from the caller; the borrow ends before the free.
        let owned = unsafe { borrow(engine.cast_const()) }?.in_owner_process();
        if !owned {
            return Ok(());
        }
        // SAFETY: forwarded from the caller.
        unsafe { free(engine) }
    })
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
            let engine = borrow_engine(engine)?;
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
            let engine = borrow_engine(engine)?;
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
            let engine = borrow_engine(engine)?;
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
            let engine = borrow_engine(engine)?;
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
        let mut out = unsafe { handle_out(out) }?;
        out.write(Box::into_raw(Box::default()));
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
/// and `error` must be null or valid for one write. A null `error` means that
/// the caller wants only the status.
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
        // SAFETY: forwarded from the caller. Both pointers are checked and
        // set to null before either error returns, so a valid `out` is null
        // even when `error` is misaligned.
        let (out, error) = unsafe { (handle_out(out), error_out(error)) };
        let (mut error, mut out) = (error?, out?);
        let status = guarded_with_error(error.as_mut(), || {
            let invalid = |message: &str| FfiError::new(ERROR_INVALID_ARGUMENT, message);
            // SAFETY: the engine and cancel handles, the scan arguments and the
            // input follow the rules that the caller guarantees.
            let (engine, cancel, request) = unsafe {
                let engine = borrow_engine(engine).map_err(|status| {
                    if status == ERROR_CLOSED {
                        FfiError::new(
                            ERROR_CLOSED,
                            "the engine was made in another process, before this process forked",
                        )
                    } else {
                        invalid("the engine handle is null or misaligned")
                    }
                })?;
                let cancel = if cancel.is_null() {
                    None
                } else {
                    let handle =
                        borrow(cancel).map_err(|_| invalid("the cancel handle is misaligned"))?;
                    Some(handle.flag())
                };
                (engine, cancel, scan_request(args)?)
            };
            // Check the length before touching the input.
            engine.check_input_size(input_len)?;
            // SAFETY: the caller guarantees the byte pointer rule for the input.
            let input = unsafe { borrow_bytes(input, input_len) }
                .map_err(|_| invalid("the input pointer is null"))?;
            let result = engine.scan(input, &request, cancel)?;
            out.write(Box::into_raw(Box::new(result)));
            Ok(())
        });
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
        // SAFETY: forwarded from the caller. Both out pointers and the
        // handle are checked before either out pointer is written.
        let (error, mut ptr_out, mut len_out) =
            unsafe { (borrow(error)?, Out::new(out_ptr)?, Out::new(out_len)?) };
        let message = Bytes::of(error.message().as_bytes());
        ptr_out.write(message.ptr);
        len_out.write(message.len);
        Ok(())
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
