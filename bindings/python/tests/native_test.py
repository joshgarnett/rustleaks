"""Checks the ctypes declarations against rustleaks.h and the library."""

from __future__ import annotations

import ctypes
import os
import re
import tomllib
import unittest
from ctypes import POINTER, byref, c_size_t
from typing import Any

import support

import rustleaks
from rustleaks import _native


def header_text() -> str:
    with open(support.header_path(), encoding="utf-8") as file:
        text = file.read()
    # Drop comments.
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


HANDLES = {
    "rustleaks_options": _native.Options,
    "rustleaks_engine": _native.Engine,
    "rustleaks_cancel": _native.Cancel,
    "rustleaks_result": _native.Result,
    "rustleaks_error": _native.Error,
}

STRUCTS = {
    "rustleaks_bytes": _native.Bytes,
    "rustleaks_scan_args": _native.ScanArgs,
    "rustleaks_rule_view": _native.RuleView,
    "rustleaks_finding_view": _native.FindingView,
    "rustleaks_status_view": _native.StatusView,
}

SCALARS = {
    "uint8_t": ctypes.c_uint8,
    "uint32_t": ctypes.c_uint32,
    "uint64_t": ctypes.c_uint64,
    "int32_t": ctypes.c_int32,
    "size_t": ctypes.c_size_t,
    "double": ctypes.c_double,
}


def ctype(declaration: str) -> Any:
    """The ctypes type that stands for a C type in the header."""
    text = declaration.replace("const ", "").strip()
    stars = text.count("*")
    base = text.replace("*", "").strip()
    if base == "uint8_t" and stars == 1:
        # Byte pointers in and byte pointers out of the library.
        return ctypes.c_char_p
    if base == "uint8_t" and stars == 2:
        return POINTER(ctypes.c_void_p)
    if base in HANDLES:
        result = HANDLES[base]
    elif base in STRUCTS:
        result = STRUCTS[base]
    else:
        result = SCALARS[base]
    for _ in range(stars):
        result = POINTER(result)
    return result


def split_declaration(text: str) -> tuple[str, str]:
    """Splits ``type name`` into the type and the name."""
    match = re.fullmatch(r"(.*?[\s*])(\w+)", text.strip(), flags=re.S)
    assert match, text
    return match.group(1).strip(), match.group(2)


def same_type(left: Any, right: Any) -> bool:
    """Compares ctypes types, including pointer types built twice."""
    if left is right:
        return True
    # A byte pointer can be declared either way; both are one pointer.
    byte_pointers = {ctypes.c_char_p, ctypes.c_void_p}
    if left in byte_pointers and right in byte_pointers:
        return True
    left_type = getattr(left, "_type_", None)
    right_type = getattr(right, "_type_", None)
    if isinstance(left_type, type) and isinstance(right_type, type):
        return issubclass(left, ctypes._Pointer) and issubclass(right, ctypes._Pointer) and (
            same_type(left_type, right_type)
        )
    return False


class HeaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = header_text()

    def test_constants_match_the_header(self) -> None:
        defines = dict(
            re.findall(r"^#define RUSTLEAKS_(\w+) (\S+)\s*$", self.header, flags=re.M)
        )
        self.assertIn("ABI_VERSION", defines)
        for name, value in defines.items():
            with self.subTest(name):
                expected = _native.UNLIMITED if value == "UINT64_MAX" else int(value)
                self.assertEqual(getattr(_native, name), expected)

    def test_structs_match_the_header(self) -> None:
        found = re.findall(
            r"typedef struct (\w+) \{(.*?)\} \1;", self.header, flags=re.S
        )
        self.assertEqual({name for name, _ in found}, set(STRUCTS))
        for name, body in found:
            with self.subTest(name):
                fields = [
                    split_declaration(line)
                    for line in body.split(";")
                    if line.strip()
                ]
                declared = STRUCTS[name]._fields_
                self.assertEqual(
                    [field for _, field in fields], [field for field, _ in declared]
                )
                for (c_type, field), (_, py_type) in zip(fields, declared):
                    self.assertTrue(
                        same_type(ctype(c_type), py_type), f"{name}.{field}: {c_type}"
                    )

    def test_struct_sizes_on_64_bit_targets(self) -> None:
        # Every supported target is 64-bit, with 8-byte pointers and
        # size_t, and 8-byte alignment of uint64_t and double.
        self.assertEqual(ctypes.sizeof(ctypes.c_void_p), 8)
        expected = {
            _native.Bytes: 16,
            _native.ScanArgs: 112,
            _native.RuleView: 64,
            _native.FindingView: 192,
            _native.StatusView: 80,
        }
        for struct, size in expected.items():
            with self.subTest(struct.__name__):
                self.assertEqual(ctypes.sizeof(struct), size)
                self.assertEqual(ctypes.alignment(struct), 8)
        self.assertEqual(_native.ScanArgs.allow_comments.offset, 104)
        self.assertEqual(_native.FindingView.entropy.offset, 176)
        self.assertEqual(_native.FindingView.match_range_exact.offset, 185)

    def test_handles_are_declared(self) -> None:
        found = set(re.findall(r"typedef struct (\w+) \1;", self.header))
        self.assertEqual(found, set(HANDLES))

    def test_functions_match_the_header(self) -> None:
        found = re.findall(r"^int32_t (rustleaks_\w+)\((.*?)\);", self.header, flags=re.M)
        self.assertEqual({name for name, _ in found}, set(_native.FUNCTIONS))
        library = _native.library()
        for name, arguments in found:
            with self.subTest(name):
                types = [ctype(split_declaration(item)[0]) for item in arguments.split(",")]
                declared = _native.FUNCTIONS[name]
                self.assertEqual(len(types), len(declared))
                for index, (c_type, py_type) in enumerate(zip(types, declared)):
                    self.assertTrue(same_type(c_type, py_type), f"{name} argument {index}")
                function = getattr(library, name)
                self.assertIs(function.restype, ctypes.c_int32)
                self.assertEqual(tuple(function.argtypes), declared)


class LibraryTest(unittest.TestCase):
    def test_default_path_is_inside_the_package(self) -> None:
        path = _native.default_library_path()
        self.assertTrue(os.path.isabs(path))
        package = os.path.dirname(os.path.abspath(rustleaks.__file__))
        self.assertEqual(os.path.dirname(path), os.path.join(package, "_native"))
        self.assertEqual(os.path.basename(path), _native.library_file_name())

    def test_file_names(self) -> None:
        self.assertEqual(_native.library_file_name("linux"), "librustleaks_ffi.so")
        self.assertEqual(_native.library_file_name("darwin"), "librustleaks_ffi.dylib")
        self.assertEqual(_native.library_file_name("win32"), "rustleaks_ffi.dll")

    def test_relative_library_path_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _native.set_library_path("librustleaks_ffi.so")

    def test_missing_library(self) -> None:
        missing = os.path.join(os.path.dirname(support.library_path()), "no-such-library")
        with self.assertRaises(rustleaks.LibraryError) as caught:
            _native.load(missing)
        self.assertIn("missing", str(caught.exception))
        self.assertEqual(caught.exception.kind, "load")

    def test_file_that_is_not_a_library(self) -> None:
        with self.assertRaises(rustleaks.LibraryError):
            _native.load(support.header_path())

    def test_version_mismatch(self) -> None:
        version = _native.__version__
        _native.__version__ = "0.0.0-other"
        try:
            with self.assertRaises(rustleaks.LibraryError) as caught:
                _native.load(support.library_path())
        finally:
            _native.__version__ = version
        self.assertIn("version", str(caught.exception))
        self.assertEqual(caught.exception.kind, "version")

    def test_library_has_the_package_version(self) -> None:
        library = _native.library()
        pointer = ctypes.c_void_p()
        length = c_size_t()
        self.assertEqual(library.rustleaks_version(byref(pointer), byref(length)), _native.OK)
        version = ctypes.string_at(pointer.value, length.value).decode()
        self.assertEqual(_native.python_version(version), rustleaks.__version__)

    def test_python_version_of_release_versions(self) -> None:
        for version, expected in [
            ("0.3.0", "0.3.0"),
            ("0.3.0-alpha.1", "0.3.0a1"),
            ("0.3.0-alpha.12", "0.3.0a12"),
            ("1.0.0-beta.2", "1.0.0b2"),
            ("1.0.0-rc.0", "1.0.0rc0"),
        ]:
            self.assertEqual(_native.python_version(version), expected, version)
        for version in [
            "0.3.0a1",
            "0.3.0-alpha",
            "0.3.0-alpha.01",
            "0.3.0-dev.1",
            "0.3.0-rc1",
            "0.3.0+build.1",
            "00.3.0",
            "0.3",
            "",
        ]:
            self.assertIsNone(_native.python_version(version), version)

    def test_pre_release_library_matches_its_package_version(self) -> None:
        # A library reports its semantic version, and the package holds the
        # PEP 440 form of it.
        def identity(native: str) -> Any:
            text = ctypes.create_string_buffer(native.encode())

            class Library:
                def rustleaks_abi_version(self, abi: Any) -> int:
                    abi._obj.value = _native.ABI_VERSION
                    return _native.OK

                def rustleaks_version(self, pointer: Any, length: Any) -> int:
                    pointer._obj.value = ctypes.addressof(text)
                    length._obj.value = len(native)
                    return _native.OK

            return Library()

        version = _native.__version__
        try:
            _native.__version__ = "0.3.0a1"
            _native._check_identity(identity("0.3.0-alpha.1"), "library")
            for native in ["0.3.0a1", "0.3.0", "0.3.0-alpha.2", "0.3.0-beta.1"]:
                with self.assertRaises(rustleaks.LibraryError, msg=native) as caught:
                    _native._check_identity(identity(native), "library")
                self.assertEqual(caught.exception.kind, "version")
                self.assertIn(native, str(caught.exception))
        finally:
            _native.__version__ = version

    def test_package_metadata(self) -> None:
        with open(support.runfile(os.environ["RUSTLEAKS_TEST_PYPROJECT"]), "rb") as file:
            project = tomllib.load(file)["project"]
        self.assertEqual(project["name"], "rustleaks")
        self.assertEqual(project["version"], rustleaks.__version__)
        self.assertEqual(project["requires-python"], ">=3.12")
        self.assertEqual(project["dependencies"], [])

    def test_abi_mismatch(self) -> None:
        library = _native.library()
        options = POINTER(_native.Options)()
        status = library.rustleaks_options_new(_native.ABI_VERSION + 1, byref(options))
        self.assertEqual(status, _native.ERROR_ABI_MISMATCH)
        self.assertFalse(options)


if __name__ == "__main__":
    unittest.main()
