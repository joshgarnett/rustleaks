"""The engine and cancel token."""

from __future__ import annotations

import ctypes
import math
import os
import threading
import time
import weakref
from collections.abc import Iterable
from ctypes import POINTER, byref, c_int32, c_size_t, c_uint64, c_void_p
from typing import Literal, NoReturn

from . import _native
from ._errors import (
    BudgetExceededError,
    ClosedError,
    ConfigError,
    Error,
    IncompleteScanError,
    InputTooLargeError,
    LibraryError,
    ScanCancelledError,
    ScanTimeoutError,
    TextEncodingError,
)
from ._types import UNLIMITED, Budget, Finding, Rule, Usage

__all__ = ["CancelToken", "Engine"]

Base64Mode = Literal["compatible", "extended"]

_BASE64_MODES = {
    "compatible": _native.BASE64_COMPATIBLE,
    "extended": _native.BASE64_EXTENDED,
}

# Budget field, engine option key, scan override bit.
_BUDGET_FIELDS = (
    ("decoded_bytes", _native.OPTION_MAX_DECODED_BYTES, _native.SCAN_SET_MAX_DECODED_BYTES),
    ("work_units", _native.OPTION_MAX_WORK_UNITS, _native.SCAN_SET_MAX_WORK_UNITS),
    (
        "finding_records",
        _native.OPTION_MAX_FINDING_RECORDS,
        _native.SCAN_SET_MAX_FINDING_RECORDS,
    ),
    (
        "finding_payload_bytes",
        _native.OPTION_MAX_FINDING_PAYLOAD_BYTES,
        _native.SCAN_SET_MAX_FINDING_PAYLOAD_BYTES,
    ),
    (
        "collected_spans",
        _native.OPTION_MAX_COLLECTED_SPANS,
        _native.SCAN_SET_MAX_COLLECTED_SPANS,
    ),
    (
        "normalization_bytes",
        _native.OPTION_MAX_NORMALIZATION_BYTES,
        _native.SCAN_SET_MAX_NORMALIZATION_BYTES,
    ),
)

_BUDGET_NAMES = {
    _native.BUDGET_DECODED_BYTES: "decoded_bytes",
    _native.BUDGET_WORK_UNITS: "work_units",
    _native.BUDGET_FINDING_RECORDS: "finding_records",
    _native.BUDGET_FINDING_PAYLOAD_BYTES: "finding_payload_bytes",
    _native.BUDGET_COLLECTED_SPANS: "collected_spans",
    _native.BUDGET_NORMALIZATION_BYTES: "normalization_bytes",
}

# How often a scan that waits for a worker checks its cancel token and
# whether the engine closed, and how often close checks for an interrupt.
_POLL_SECONDS = 0.05


def _no_pickle(value: object) -> NoReturn:
    raise TypeError(f"cannot pickle a rustleaks {type(value).__name__}")


def _no_copy(value: object) -> NoReturn:
    raise TypeError(f"cannot copy a rustleaks {type(value).__name__}")


def _check_int(name: str, value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, not {type(value).__name__}")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be from {minimum} to {maximum}")
    return int(value)


def _check_bool(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool, not {type(value).__name__}")
    return value


def _check_base64_mode(value: object) -> int:
    if not isinstance(value, str):
        raise TypeError(f"base64_mode must be a str, not {type(value).__name__}")
    try:
        return _BASE64_MODES[value]
    except KeyError:
        pass
    raise ValueError('base64_mode must be "compatible" or "extended"')


def _check_budget(value: object) -> Budget:
    if not isinstance(value, Budget):
        raise TypeError(f"budget must be a rustleaks.Budget, not {type(value).__name__}")
    return value


def _check_timeout(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"timeout must be a number or None, not {type(value).__name__}")
    seconds = float(value)
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("timeout must be a finite number of seconds, 0 or more")
    return seconds


def _encode_text(name: str, value: str) -> bytes:
    """Encodes text as strict UTF-8. The error does not chain the
    UnicodeEncodeError, which holds the text."""
    position = -1
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        position = error.start
    raise TextEncodingError(
        f"{name} cannot be encoded as UTF-8: the character at index {position} "
        "is a lone surrogate",
        position,
    )


def _check_path(value: object) -> tuple[str | None, bytes]:
    if value is None:
        return None, b""
    path = os.fspath(value) if isinstance(value, os.PathLike) else value
    if not isinstance(path, str):
        raise TypeError(f"path must be a str or None, not {type(value).__name__}")
    if not path:
        return None, b""
    return path, _encode_text("path", path)


def _status_error(kind: int, message: str) -> Error:
    if kind == _native.ERROR_CONFIG:
        return ConfigError(message, "config")
    if kind == _native.ERROR_RULE_SELECTION:
        return ConfigError(message, "rule_selection")
    if kind == _native.ERROR_ABI_MISMATCH:
        return LibraryError(message)
    return Error(message)


def _take_error(library: ctypes.CDLL, status: int, error: ctypes._Pointer[_native.Error]) -> Error:
    """Reads the message of a native error. The caller frees the handle."""
    message = f"rustleaks error {status}"
    if error:
        pointer = c_void_p()
        length = c_size_t()
        if library.rustleaks_error_message(error, byref(pointer), byref(length)) == _native.OK:
            message = ctypes.string_at(pointer.value or 0, length.value).decode(
                "utf-8", "replace"
            )
        kind = c_int32()
        if library.rustleaks_error_kind(error, byref(kind)) == _native.OK:
            status = kind.value
    return _status_error(status, message)


def _check(status: int, what: str) -> None:
    if status != _native.OK:
        raise Error(f"rustleaks {what} failed with status {status}")


class CancelToken:
    """Stops the scans that it is passed to.

    ``cancel()`` can be called from any thread, before or during a scan. A
    cancelled token stays cancelled, and every scan that uses it raises
    ``ScanCancelledError``. One token can serve many scans.
    """

    __slots__ = ("__weakref__", "_cancelled", "_handle", "_library")

    def __init__(self) -> None:
        self._handle = POINTER(_native.Cancel)()
        self._cancelled = False
        self._library = _native.library()
        _check(self._library.rustleaks_cancel_new(byref(self._handle)), "cancel_new")

    def cancel(self) -> None:
        """Cancels every scan that uses this token, now and later."""
        self._cancelled = True
        _check(self._library.rustleaks_cancel_set(self._handle), "cancel_set")

    @property
    def cancelled(self) -> bool:
        """Whether ``cancel()`` was called."""
        return self._cancelled

    def __repr__(self) -> str:
        state = "cancelled" if self._cancelled else "not cancelled"
        return f"<rustleaks.CancelToken {state}>"

    def __del__(self) -> None:
        # A scan holds a reference to its token, so no scan uses the handle
        # when the token is collected.
        handle = getattr(self, "_handle", None)
        if handle:
            self._handle = POINTER(_native.Cancel)()
            try:
                self._library.rustleaks_cancel_free(handle)
            except Exception:
                pass

    __reduce_ex__ = _no_pickle  # type: ignore[assignment]
    __copy__ = _no_copy

    def __deepcopy__(self, memo: object) -> NoReturn:
        _no_copy(self)


_live_engines: weakref.WeakSet[Engine] = weakref.WeakSet()


class Engine:
    """A compiled set of rules that scans bytes for secrets.

    With no arguments the engine has every built-in rule. ``config`` is a
    TOML configuration that replaces the built-in rules; with
    ``[extend] useDefault = true`` it adds to them. ``[extend] path`` fails,
    because the package reads no files. ``rules`` keeps only the named
    rules. The other options set the defaults of every scan; ``None`` keeps
    the library default.

    An engine can scan on many threads at once. It runs at most ``workers``
    scans at a time; other scans wait for a free worker. Building an engine
    compiles every rule, so build it once and reuse it. Close it with
    ``close()`` or a ``with`` block.
    """

    def __init__(
        self,
        *,
        rules: Iterable[str] | None = None,
        config: str | bytes | None = None,
        workers: int | None = None,
        max_input_bytes: int | None = None,
        budget: Budget | None = None,
        allow_comments: bool | None = None,
        decode_depth: int | None = None,
        base64_mode: Base64Mode | None = None,
        redaction: int | None = None,
    ) -> None:
        self._handle = POINTER(_native.Engine)()
        self._closed = True
        settings = _engine_settings(
            rules=rules,
            config=config,
            workers=workers,
            max_input_bytes=max_input_bytes,
            budget=budget,
            allow_comments=allow_comments,
            decode_depth=decode_depth,
            base64_mode=base64_mode,
            redaction=redaction,
        )
        library = _native.library()
        self._library = library
        options = POINTER(_native.Options)()
        error = POINTER(_native.Error)()
        try:
            _check(
                library.rustleaks_options_new(_native.ABI_VERSION, byref(options)),
                "options_new",
            )
            settings.apply(library, options)
            # The handle is written into self._handle, so an interrupt right
            # after the call still leaves it for __del__ to free.
            status = library.rustleaks_engine_new(options, byref(self._handle), byref(error))
            if status != _native.OK:
                raise _take_error(library, status, error)
        finally:
            _release(library.rustleaks_error_free, error)
            _release(library.rustleaks_options_free, options)
        count = c_size_t()
        _check(library.rustleaks_engine_workers(self._handle, byref(count)), "engine_workers")
        self._workers = count.value
        # The package checks sizes with the engine's own limit before each
        # native call, and the library checks again.
        limit = c_uint64()
        _check(
            library.rustleaks_engine_max_input_bytes(self._handle, byref(limit)),
            "engine_max_input_bytes",
        )
        self._max_input_bytes = limit.value
        self._rules = _read_rules(library, self._handle)
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._slots = threading.Semaphore(self._workers)
        self._in_flight = 0
        self._closed = False
        _live_engines.add(self)

    @property
    def workers(self) -> int:
        """How many scans the engine runs at once."""
        return self._workers

    @property
    def max_input_bytes(self) -> int:
        """The longest input in bytes, or ``UNLIMITED`` when there is no
        limit."""
        return self._max_input_bytes

    @property
    def closed(self) -> bool:
        """Whether the engine is closed."""
        return self._closed

    def rules(self) -> list[Rule]:
        """The rules that can report findings, in report order."""
        return list(self._rules)

    def scan(
        self,
        data: bytes | bytearray | memoryview,
        *,
        path: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
        cancel: CancelToken | None = None,
        budget: Budget | None = None,
        allow_comments: bool | None = None,
        decode_depth: int | None = None,
        base64_mode: Base64Mode | None = None,
        redaction: int | None = None,
    ) -> list[Finding]:
        """Scans bytes and returns the findings in report order.

        ``data`` is any bytes-like object. A ``bytes`` object is scanned
        without a copy in Python; any other object is copied once, before the
        scan, so changes to it during the scan do not matter. ``path`` is
        the path that path rules and path allowlists test, and that findings
        report. ``timeout`` in seconds covers the wait for a worker and the
        scan. The other options override the engine's options for this scan.

        Raises ``InputTooLargeError`` when the input is longer than the
        engine's input limit, ``ScanCancelledError``, ``ScanTimeoutError`` or
        ``BudgetExceededError`` when the scan stops early, and
        ``ClosedError`` when the engine is closed.
        """
        if isinstance(data, str):
            raise TypeError("scan() needs a bytes-like object; use scan_text() for str")
        try:
            view = memoryview(data)
        except TypeError:
            raise TypeError(
                f"scan() needs a bytes-like object, not {type(data).__name__}"
            ) from None
        with view:
            size = view.nbytes
            request = _scan_request(
                path=path,
                timeout=timeout,
                cancel=cancel,
                budget=budget,
                allow_comments=allow_comments,
                decode_depth=decode_depth,
                base64_mode=base64_mode,
                redaction=redaction,
            )
            self._check_size(size)
            if type(data) is bytes:
                payload = data
            else:
                payload = view.tobytes()
        return self._run(payload, request)

    def scan_text(
        self,
        text: str,
        *,
        path: str | os.PathLike[str] | None = None,
        timeout: float | None = None,
        cancel: CancelToken | None = None,
        budget: Budget | None = None,
        allow_comments: bool | None = None,
        decode_depth: int | None = None,
        base64_mode: Base64Mode | None = None,
        redaction: int | None = None,
    ) -> list[Finding]:
        """Scans text encoded as strict UTF-8, as ``scan`` scans bytes.

        Byte offsets and columns in the findings count UTF-8 bytes, not
        characters. Raises ``TextEncodingError`` for text that UTF-8 cannot
        encode, such as a lone surrogate.
        """
        if not isinstance(text, str):
            raise TypeError(f"scan_text() needs a str, not {type(text).__name__}")
        request = _scan_request(
            path=path,
            timeout=timeout,
            cancel=cancel,
            budget=budget,
            allow_comments=allow_comments,
            decode_depth=decode_depth,
            base64_mode=base64_mode,
            redaction=redaction,
        )
        # Every character takes at least one byte, so a long text fails
        # before it is encoded.
        self._check_size(len(text))
        payload = _encode_text("text", text)
        self._check_size(len(payload))
        return self._run(payload, request)

    def close(self) -> None:
        """Closes the engine and frees it.

        New scans raise ``ClosedError``. Running scans are not cancelled:
        ``close`` waits until they return. Calling ``close`` again does
        nothing.
        """
        lock = getattr(self, "_lock", None)
        if lock is None:
            return
        with self._idle:
            self._closed = True
            while self._in_flight:
                # A short wait lets an interrupt reach this thread.
                self._idle.wait(_POLL_SECONDS)
            handle = self._handle
            if handle:
                self._handle = POINTER(_native.Engine)()
                _check(self._library.rustleaks_engine_free(handle), "engine_free")
        _live_engines.discard(self)

    def __enter__(self) -> Engine:
        if self._closed:
            raise ClosedError("the engine is closed")
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        rules = len(getattr(self, "_rules", ()))
        workers = getattr(self, "_workers", 0)
        return f"<rustleaks.Engine {state} rules={rules} workers={workers}>"

    def __del__(self) -> None:
        # Every scan holds a reference to its engine, so no scan uses the
        # handle when the engine is collected.
        handle = getattr(self, "_handle", None)
        if handle:
            self._handle = POINTER(_native.Engine)()
            try:
                self._library.rustleaks_engine_free(handle)
            except Exception:
                pass

    __reduce_ex__ = _no_pickle  # type: ignore[assignment]
    __copy__ = _no_copy

    def __deepcopy__(self, memo: object) -> NoReturn:
        _no_copy(self)

    def _check_size(self, size: int) -> None:
        limit = self._max_input_bytes
        if limit != UNLIMITED and size > limit:
            raise InputTooLargeError(
                f"the input is longer than the limit of {limit} bytes",
                size,
                limit,
            )

    def _after_fork_in_child(self) -> None:
        # The engine's scan threads do not exist in the child, so the handle
        # is dropped without freeing it. The locks may have been held by a
        # thread of the parent.
        self._handle = POINTER(_native.Engine)()
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._slots = threading.Semaphore(self._workers)
        self._in_flight = 0
        self._closed = True

    def _acquire(self, deadline: float | None, cancel: CancelToken | None) -> None:
        """Waits for a free worker."""
        while True:
            if self._closed:
                raise ClosedError("the engine is closed")
            if cancel is not None and cancel.cancelled:
                raise ScanCancelledError(
                    "the scan was cancelled before it started",
                    termination="cancelled",
                    usage=Usage(),
                )
            wait = _POLL_SECONDS
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ScanTimeoutError(
                        "the timeout passed while the scan waited for a worker",
                        termination="timeout",
                        usage=Usage(),
                    )
                wait = min(wait, remaining)
            if self._slots.acquire(timeout=wait):
                return

    def _run(self, payload: bytes, request: _ScanRequest) -> list[Finding]:
        if self._closed:
            raise ClosedError("the engine is closed")
        deadline = None
        if request.timeout is not None:
            deadline = time.monotonic() + request.timeout
        self._acquire(deadline, request.cancel)
        try:
            with self._lock:
                if self._closed:
                    raise ClosedError("the engine is closed")
                self._in_flight += 1
                handle = self._handle
            try:
                return self._scan_native(handle, payload, request, deadline)
            finally:
                with self._idle:
                    self._in_flight -= 1
                    if not self._in_flight:
                        self._idle.notify_all()
        finally:
            self._slots.release()

    def _scan_native(
        self,
        handle: ctypes._Pointer[_native.Engine],
        payload: bytes,
        request: _ScanRequest,
        deadline: float | None,
    ) -> list[Finding]:
        library = self._library
        args = request.args
        if deadline is not None:
            remaining = max(0.0, deadline - time.monotonic())
            args.overrides |= _native.SCAN_SET_DEADLINE
            args.deadline_ns = min(int(remaining * 1e9), UNLIMITED)
        cancel = request.cancel._handle if request.cancel is not None else None
        result = POINTER(_native.Result)()
        error = POINTER(_native.Error)()
        try:
            status = library.rustleaks_scan(
                handle,
                payload,
                len(payload),
                byref(args),
                cancel,
                byref(result),
                byref(error),
            )
            if status != _native.OK:
                failure = _take_error(library, status, error)
                if status == _native.ERROR_INPUT_TOO_LARGE:
                    limit = self._max_input_bytes
                    raise InputTooLargeError(str(failure), len(payload), limit)
                raise failure
            return _read_result(library, result, request.path)
        finally:
            _release(library.rustleaks_error_free, error)
            _release(library.rustleaks_result_free, result)


def _release(free: object, box: ctypes._Pointer[object]) -> None:
    """Frees the handle in ``box``. It clears the box first, so an interrupt
    between the two leaks the handle but never frees it twice."""
    if box:
        handle = ctypes.cast(box, type(box))
        ctypes.memset(ctypes.addressof(box), 0, ctypes.sizeof(box))
        free(handle)  # type: ignore[operator]


class _EngineSettings:
    __slots__ = ("bools", "config", "rule_ids", "u64")

    def __init__(self) -> None:
        self.config: bytes | None = None
        self.rule_ids: list[bytes] = []
        self.u64: list[tuple[int, int]] = []
        self.bools: list[tuple[int, int]] = []

    def apply(self, library: ctypes.CDLL, options: ctypes._Pointer[_native.Options]) -> None:
        if self.config is not None:
            _check(
                library.rustleaks_options_set_config(options, self.config, len(self.config)),
                "options_set_config",
            )
        for rule_id in self.rule_ids:
            _check(
                library.rustleaks_options_add_rule_id(options, rule_id, len(rule_id)),
                "options_add_rule_id",
            )
        for key, value in self.u64:
            _check(library.rustleaks_options_set_u64(options, key, value), "options_set_u64")
        for key, flag in self.bools:
            _check(library.rustleaks_options_set_bool(options, key, flag), "options_set_bool")


def _engine_settings(
    *,
    rules: Iterable[str] | None,
    config: str | bytes | None,
    workers: int | None,
    max_input_bytes: int | None,
    budget: Budget | None,
    allow_comments: bool | None,
    decode_depth: int | None,
    base64_mode: Base64Mode | None,
    redaction: int | None,
) -> _EngineSettings:
    settings = _EngineSettings()
    if config is not None:
        if isinstance(config, str):
            settings.config = _encode_text("config", config)
        elif isinstance(config, (bytes, bytearray, memoryview)):
            settings.config = bytes(config)
        else:
            raise TypeError(f"config must be a str or bytes, not {type(config).__name__}")
    if rules is not None:
        if isinstance(rules, (str, bytes)):
            raise TypeError("rules must be a list of rule IDs, not one string")
        for rule_id in rules:
            if not isinstance(rule_id, str):
                raise TypeError(f"each rule ID must be a str, not {type(rule_id).__name__}")
            settings.rule_ids.append(_encode_text("rule ID", rule_id))
        if not settings.rule_ids:
            raise ValueError("rules must name at least one rule; pass None for every rule")
    if workers is not None:
        value = _check_int("workers", workers, 1, _native.MAX_WORKERS)
        settings.u64.append((_native.OPTION_WORKERS, value))
    if max_input_bytes is not None:
        value = _check_int("max_input_bytes", max_input_bytes, 0, UNLIMITED)
        settings.u64.append((_native.OPTION_MAX_INPUT_BYTES, value))
    if budget is not None:
        for name, key, _bit in _BUDGET_FIELDS:
            limit = getattr(_check_budget(budget), name)
            if limit is not None:
                settings.u64.append((key, limit))
    if allow_comments is not None:
        flag = _check_bool("allow_comments", allow_comments)
        settings.bools.append((_native.OPTION_ALLOW_COMMENTS, int(flag)))
    if decode_depth is not None:
        value = _check_int("decode_depth", decode_depth, 0, UNLIMITED)
        settings.u64.append((_native.OPTION_DECODE_DEPTH, value))
    if base64_mode is not None:
        settings.u64.append((_native.OPTION_BASE64_MODE, _check_base64_mode(base64_mode)))
    if redaction is not None:
        value = _check_int("redaction", redaction, 0, 100)
        settings.u64.append((_native.OPTION_REDACTION_PERCENT, value))
    return settings


class _ScanRequest:
    __slots__ = ("args", "cancel", "path", "timeout")

    def __init__(
        self,
        args: _native.ScanArgs,
        path: str | None,
        timeout: float | None,
        cancel: CancelToken | None,
    ) -> None:
        self.args = args
        self.path = path
        self.timeout = timeout
        self.cancel = cancel


def _scan_request(
    *,
    path: object,
    timeout: object,
    cancel: object,
    budget: object,
    allow_comments: object,
    decode_depth: object,
    base64_mode: object,
    redaction: object,
) -> _ScanRequest:
    args = _native.ScanArgs()
    text_path, path_bytes = _check_path(path)
    if path_bytes:
        args.path = path_bytes
        args.path_len = len(path_bytes)
    seconds = _check_timeout(timeout)
    if cancel is not None and not isinstance(cancel, CancelToken):
        raise TypeError(f"cancel must be a rustleaks.CancelToken, not {type(cancel).__name__}")
    overrides = 0
    if budget is not None:
        for name, _key, bit in _BUDGET_FIELDS:
            limit = getattr(_check_budget(budget), name)
            if limit is not None:
                overrides |= bit
                setattr(args, "max_" + name, limit)
    if allow_comments is not None:
        overrides |= _native.SCAN_SET_ALLOW_COMMENTS
        args.allow_comments = int(_check_bool("allow_comments", allow_comments))
    if decode_depth is not None:
        overrides |= _native.SCAN_SET_DECODE_DEPTH
        args.decode_depth = _check_int("decode_depth", decode_depth, 0, UNLIMITED)
    if base64_mode is not None:
        overrides |= _native.SCAN_SET_BASE64_MODE
        args.base64_mode = _check_base64_mode(base64_mode)
    if redaction is not None:
        overrides |= _native.SCAN_SET_REDACTION_PERCENT
        args.redaction_percent = _check_int("redaction", redaction, 0, 100)
    args.overrides = overrides
    return _ScanRequest(args, text_path, seconds, cancel)  # type: ignore[arg-type]


def _read_rules(library: ctypes.CDLL, handle: ctypes._Pointer[_native.Engine]) -> tuple[Rule, ...]:
    count = c_size_t()
    _check(library.rustleaks_engine_rule_count(handle, byref(count)), "engine_rule_count")
    rules = []
    view = _native.RuleView()
    for index in range(count.value):
        _check(library.rustleaks_engine_rule(handle, index, byref(view)), "engine_rule")
        rules.append(
            Rule(
                id=_native.read_text(view.id),
                description=_native.read_text(view.description),
                tags=_native.read_list(view.tags, view.tag_count),
                keywords=_native.read_list(view.keywords, view.keyword_count),
            )
        )
    return tuple(rules)


def _usage(status: _native.StatusView) -> Usage:
    return Usage(
        decoded_bytes=status.decoded_bytes,
        work_units=status.work_units,
        finding_records=status.finding_records,
        finding_payload_bytes=status.finding_payload_bytes,
        collected_spans=status.collected_spans,
        normalization_bytes=status.normalization_bytes,
    )


def _incomplete(status: _native.StatusView) -> IncompleteScanError:
    usage = _usage(status)
    termination = status.termination
    if termination == _native.TERMINATION_CANCELLED:
        return ScanCancelledError(
            "the scan was cancelled", termination="cancelled", usage=usage
        )
    if termination == _native.TERMINATION_DEADLINE:
        return ScanTimeoutError(
            "the timeout passed before the scan finished", termination="timeout", usage=usage
        )
    if termination == _native.TERMINATION_BUDGET:
        budget = _BUDGET_NAMES.get(status.budget)
        return BudgetExceededError(
            f"the scan stopped because the {budget or 'unknown'} budget ran out "
            f"(limit {status.limit}, used {status.consumed}, "
            f"asked for {status.requested})",
            termination="budget",
            usage=usage,
            budget=budget,  # type: ignore[arg-type]
            limit=status.limit,
            consumed=status.consumed,
            requested=status.requested,
        )
    return IncompleteScanError(
        "the scan stopped early for a reason this version does not name",
        termination="other",
        usage=usage,
    )


def _read_result(
    library: ctypes.CDLL, result: ctypes._Pointer[_native.Result], path: str | None
) -> list[Finding]:
    status = _native.StatusView()
    _check(library.rustleaks_result_status(result, byref(status)), "result_status")
    if status.termination != _native.TERMINATION_COMPLETE:
        raise _incomplete(status)
    count = c_size_t()
    _check(library.rustleaks_result_count(result, byref(count)), "result_count")
    findings = []
    view = _native.FindingView()
    # Equal line views share one bytes object, and equal rule text one str.
    lines: dict[tuple[int | None, int], bytes] = {}
    texts: dict[bytes, str] = {}
    tag_lists: dict[tuple[str, ...], tuple[str, ...]] = {}

    def text(field: _native.Bytes) -> str:
        raw = _native.read_bytes(field)
        value = texts.get(raw)
        if value is None:
            value = texts[raw] = raw.decode("utf-8")
        return value

    for index in range(count.value):
        _check(library.rustleaks_result_finding(result, index, byref(view)), "result_finding")
        key = (view.line.ptr, view.line.len)
        line = lines.get(key)
        if line is None:
            line = lines[key] = _native.read_bytes(view.line)
        tags = tuple(text(view.tags[i]) for i in range(view.tag_count))
        tags = tag_lists.setdefault(tags, tags)
        findings.append(
            Finding(
                rule_id=text(view.rule_id),
                description=text(view.description),
                tags=tags,
                secret=_native.read_bytes(view.secret),
                match=_native.read_bytes(view.match_text),
                line=line,
                start_line=view.start_line,
                end_line=view.end_line,
                start_column=view.start_column,
                end_column=view.end_column,
                secret_range=(
                    range(view.secret_start, view.secret_end) if view.secret_range_exact else None
                ),
                match_range=(
                    range(view.match_start, view.match_end) if view.match_range_exact else None
                ),
                entropy=view.entropy,
                path=path,
            )
        )
    return findings


def _after_fork_in_child() -> None:
    _native.reset_lock_after_fork()
    for engine in list(_live_engines):
        engine._after_fork_in_child()
    _live_engines.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
