"""ctypes declarations of the Rustleaks C ABI.

Every export of ``rustleaks.h`` is declared here with its ``argtypes`` and
``restype``, and every struct with its fields in header order. The tests
compare this module with the header. The header is private to this
repository and changes with every ABI number, so the package and the library
always ship together.

The library is loaded once, by absolute path, from the ``_native`` folder
next to this file, where the wheel puts it. Nothing searches the current
folder or ``PATH``. ``ctypes.CDLL`` releases the GIL during every call.

The folder ``_native/`` and this module ``_native.py`` share a name. Python
imports the module, because a folder without ``__init__.py`` is only a
namespace package, which loses to a module of the same name.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from ctypes import (
    POINTER,
    Structure,
    c_char_p,
    c_double,
    c_int32,
    c_size_t,
    c_uint8,
    c_uint32,
    c_uint64,
    c_void_p,
)
from typing import Any

from ._errors import LibraryError
from ._version import __version__

ABI_VERSION = 1

OK = 0
ERROR_INVALID_ARGUMENT = 1
ERROR_ABI_MISMATCH = 2
ERROR_CONFIG = 3
ERROR_RULE_SELECTION = 4
ERROR_ENGINE = 5
ERROR_INPUT_TOO_LARGE = 6
ERROR_CLOSED = 7
ERROR_PANIC = 8

UNLIMITED = 2**64 - 1

OPTION_DECODE_DEPTH = 1
OPTION_BASE64_MODE = 2
OPTION_REDACTION_PERCENT = 3
OPTION_MAX_INPUT_BYTES = 4
OPTION_MAX_DECODED_BYTES = 5
OPTION_MAX_WORK_UNITS = 6
OPTION_MAX_FINDING_RECORDS = 7
OPTION_MAX_FINDING_PAYLOAD_BYTES = 8
OPTION_MAX_COLLECTED_SPANS = 9
OPTION_MAX_NORMALIZATION_BYTES = 10
OPTION_WORKERS = 11
MAX_WORKERS = 256

OPTION_ALLOW_COMMENTS = 1
OPTION_SCAN_ON_CALLER_THREAD = 2

BASE64_COMPATIBLE = 0
BASE64_EXTENDED = 1

SCAN_SET_DECODE_DEPTH = 1
SCAN_SET_BASE64_MODE = 2
SCAN_SET_REDACTION_PERCENT = 4
SCAN_SET_ALLOW_COMMENTS = 8
SCAN_SET_MAX_DECODED_BYTES = 16
SCAN_SET_MAX_WORK_UNITS = 32
SCAN_SET_MAX_FINDING_RECORDS = 64
SCAN_SET_MAX_FINDING_PAYLOAD_BYTES = 128
SCAN_SET_MAX_COLLECTED_SPANS = 256
SCAN_SET_MAX_NORMALIZATION_BYTES = 512
SCAN_SET_DEADLINE = 1024
SCAN_SET_ALL = 2047

TERMINATION_COMPLETE = 0
TERMINATION_CANCELLED = 1
TERMINATION_DEADLINE = 2
TERMINATION_BUDGET = 3
TERMINATION_OTHER = 4

BUDGET_NONE = 0
BUDGET_DECODED_BYTES = 1
BUDGET_WORK_UNITS = 2
BUDGET_FINDING_RECORDS = 3
BUDGET_FINDING_PAYLOAD_BYTES = 4
BUDGET_COLLECTED_SPANS = 5
BUDGET_NORMALIZATION_BYTES = 6


# Opaque handle types. Distinct pointer types make ctypes reject a handle of
# the wrong kind.
class Options(Structure):
    pass


class Engine(Structure):
    pass


class Cancel(Structure):
    pass


class Result(Structure):
    pass


class Error(Structure):
    pass


class Bytes(Structure):
    _fields_ = [
        ("ptr", c_void_p),
        ("len", c_size_t),
    ]


class ScanArgs(Structure):
    _fields_ = [
        ("path", c_char_p),
        ("path_len", c_size_t),
        ("overrides", c_uint64),
        ("decode_depth", c_uint64),
        ("base64_mode", c_uint64),
        ("redaction_percent", c_uint64),
        ("max_decoded_bytes", c_uint64),
        ("max_work_units", c_uint64),
        ("max_finding_records", c_uint64),
        ("max_finding_payload_bytes", c_uint64),
        ("max_collected_spans", c_uint64),
        ("max_normalization_bytes", c_uint64),
        ("deadline_ns", c_uint64),
        ("allow_comments", c_uint8),
    ]


class RuleView(Structure):
    _fields_ = [
        ("id", Bytes),
        ("description", Bytes),
        ("tags", POINTER(Bytes)),
        ("tag_count", c_size_t),
        ("keywords", POINTER(Bytes)),
        ("keyword_count", c_size_t),
    ]


class FindingView(Structure):
    _fields_ = [
        ("rule_id", Bytes),
        ("description", Bytes),
        ("tags", POINTER(Bytes)),
        ("tag_count", c_size_t),
        ("secret", Bytes),
        ("match_text", Bytes),
        ("line", Bytes),
        ("path", Bytes),
        ("start_line", c_uint64),
        ("end_line", c_uint64),
        ("start_column", c_uint64),
        ("end_column", c_uint64),
        ("secret_start", c_uint64),
        ("secret_end", c_uint64),
        ("match_start", c_uint64),
        ("match_end", c_uint64),
        ("entropy", c_double),
        ("secret_range_exact", c_uint8),
        ("match_range_exact", c_uint8),
    ]


class StatusView(Structure):
    _fields_ = [
        ("termination", c_int32),
        ("budget", c_int32),
        ("limit", c_uint64),
        ("consumed", c_uint64),
        ("requested", c_uint64),
        ("decoded_bytes", c_uint64),
        ("work_units", c_uint64),
        ("finding_records", c_uint64),
        ("finding_payload_bytes", c_uint64),
        ("collected_spans", c_uint64),
        ("normalization_bytes", c_uint64),
    ]


_u8_ptr = c_char_p
_out_bytes = POINTER(c_void_p)

# Every export: name, argument types. Every export returns int32_t.
FUNCTIONS: dict[str, tuple[Any, ...]] = {
    "rustleaks_abi_version": (POINTER(c_uint32),),
    "rustleaks_version": (_out_bytes, POINTER(c_size_t)),
    "rustleaks_options_new": (c_uint32, POINTER(POINTER(Options))),
    "rustleaks_options_set_config": (POINTER(Options), _u8_ptr, c_size_t),
    "rustleaks_options_add_rule_id": (POINTER(Options), _u8_ptr, c_size_t),
    "rustleaks_options_set_u64": (POINTER(Options), c_uint32, c_uint64),
    "rustleaks_options_set_bool": (POINTER(Options), c_uint32, c_uint8),
    "rustleaks_options_free": (POINTER(Options),),
    "rustleaks_engine_new": (
        POINTER(Options),
        POINTER(POINTER(Engine)),
        POINTER(POINTER(Error)),
    ),
    "rustleaks_engine_free": (POINTER(Engine),),
    "rustleaks_engine_workers": (POINTER(Engine), POINTER(c_size_t)),
    "rustleaks_engine_max_input_bytes": (POINTER(Engine), POINTER(c_uint64)),
    "rustleaks_engine_rule_count": (POINTER(Engine), POINTER(c_size_t)),
    "rustleaks_engine_rule": (POINTER(Engine), c_size_t, POINTER(RuleView)),
    "rustleaks_cancel_new": (POINTER(POINTER(Cancel)),),
    "rustleaks_cancel_set": (POINTER(Cancel),),
    "rustleaks_cancel_free": (POINTER(Cancel),),
    "rustleaks_scan": (
        POINTER(Engine),
        _u8_ptr,
        c_size_t,
        POINTER(ScanArgs),
        POINTER(Cancel),
        POINTER(POINTER(Result)),
        POINTER(POINTER(Error)),
    ),
    "rustleaks_result_status": (POINTER(Result), POINTER(StatusView)),
    "rustleaks_result_count": (POINTER(Result), POINTER(c_size_t)),
    "rustleaks_result_finding": (POINTER(Result), c_size_t, POINTER(FindingView)),
    "rustleaks_result_free": (POINTER(Result),),
    "rustleaks_error_kind": (POINTER(Error), POINTER(c_int32)),
    "rustleaks_error_message": (POINTER(Error), _out_bytes, POINTER(c_size_t)),
    "rustleaks_error_free": (POINTER(Error),),
}


def library_file_name(platform: str = sys.platform) -> str:
    """The file name of the shared library on ``platform``."""
    if platform == "win32":
        return "rustleaks_ffi.dll"
    if platform == "darwin":
        return "librustleaks_ffi.dylib"
    return "librustleaks_ffi.so"


def default_library_path() -> str:
    """The absolute path of the library inside the installed package."""
    package = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(package, "_native", library_file_name())


_lock = threading.Lock()
_library: ctypes.CDLL | None = None
_library_path: str | None = None


def set_library_path(path: str) -> None:
    """Loads the library from ``path`` instead of the package folder.

    For the package's own tests, which load the library that Bazel built.
    It must be called before the first engine or token, with an absolute
    path.
    """
    global _library_path
    if not os.path.isabs(path):
        raise ValueError("the library path must be absolute")
    with _lock:
        if _library is not None and path != _library_path:
            raise RuntimeError("the native library is already loaded")
        _library_path = path


def _declare(library: ctypes.CDLL) -> None:
    for name, argtypes in FUNCTIONS.items():
        function = getattr(library, name)
        function.argtypes = argtypes
        function.restype = c_int32


def _check_identity(library: ctypes.CDLL, path: str) -> None:
    abi = c_uint32()
    if library.rustleaks_abi_version(ctypes.byref(abi)) != OK:
        raise LibraryError(f"cannot read the ABI number of {path}", "version")
    if abi.value != ABI_VERSION:
        raise LibraryError(
            f"{path} has ABI number {abi.value}, but this package needs {ABI_VERSION}",
            "version",
        )
    pointer = c_void_p()
    length = c_size_t()
    if library.rustleaks_version(ctypes.byref(pointer), ctypes.byref(length)) != OK:
        raise LibraryError(f"cannot read the version of {path}", "version")
    version = ctypes.string_at(pointer.value or 0, length.value).decode("utf-8", "replace")
    if version != __version__:
        raise LibraryError(
            f"{path} has version {version}, but this package has version {__version__}",
            "version",
        )


def load(path: str) -> ctypes.CDLL:
    """Loads the library at ``path``, declares its exports and checks its ABI
    number and version.

    Raises ``LibraryError`` when the file is missing, cannot load (for
    example a library for another architecture), lacks an export, or has
    another ABI number or version.
    """
    if not os.path.isfile(path):
        raise LibraryError(f"the Rustleaks native library is missing: {path}")
    try:
        # An absolute path, so the library itself is never searched for. On
        # Windows its dependencies are searched in its own folder, the
        # application folder, the system folders and folders added with
        # os.add_dll_directory. The library needs only system DLLs.
        loaded = ctypes.CDLL(path)
    except OSError as error:
        raise LibraryError(f"cannot load the Rustleaks native library {path}: {error}") from error
    try:
        _declare(loaded)
    except AttributeError as error:
        raise LibraryError(f"{path} lacks an export: {error}") from error
    _check_identity(loaded, path)
    return loaded


def library() -> ctypes.CDLL:
    """Loads the library once and returns it. A failed load raises
    ``LibraryError`` and is tried again on the next call."""
    global _library
    loaded = _library
    if loaded is not None:
        return loaded
    with _lock:
        if _library is None:
            _library = load(_library_path or default_library_path())
        return _library


def reset_lock_after_fork() -> None:
    """Replaces the load lock in a forked child, where another thread of the
    parent may have held it."""
    global _lock
    _lock = threading.Lock()


def read_bytes(view: Bytes) -> bytes:
    """Copies the bytes of a view."""
    if not view.len:
        return b""
    return ctypes.string_at(view.ptr, view.len)


def read_text(view: Bytes) -> str:
    """Copies the UTF-8 text of a view."""
    return read_bytes(view).decode("utf-8")


def read_list(pointer: Any, count: int) -> tuple[str, ...]:
    """Copies ``count`` UTF-8 strings from an array of views."""
    if not count:
        return ()
    return tuple(read_text(pointer[index]) for index in range(count))
