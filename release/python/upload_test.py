"""Tests for upload.py: the PyPI upload form."""

import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import upload  # noqa: E402

# The form field names that PyPI's upload endpoint reads (Warehouse
# forklift) and that twine sends for core metadata 2.4, plus the fields of
# the upload itself. A name outside this list is silently dropped by PyPI.
WAREHOUSE_FIELDS = {
    ":action",
    "protocol_version",
    "metadata_version",
    "name",
    "version",
    "summary",
    "description",
    "description_content_type",
    "keywords",
    "license_expression",
    "license_file",
    "classifiers",
    "project_urls",
    "requires_python",
    "requires_dist",
    "filetype",
    "pyversion",
    "sha256_digest",
}

METADATA = """Metadata-Version: 2.4
Name: rustleaks
Version: 1.2.3
Summary: Scan bytes and text for secrets
Description-Content-Type: text/markdown
Requires-Python: >=3.12
License-Expression: MIT
Keywords: a,b
Classifier: Programming Language :: Python :: 3
Project-URL: Homepage, https://example.com/
License-File: LICENSE
License-File: third-party/index.json

# Readme
"""


class FormTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.wheel = os.path.join(self.directory.name, "rustleaks-1.2.3-py3-none-any.whl")
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("rustleaks/__init__.py", "")
            archive.writestr("rustleaks-1.2.3.dist-info/METADATA", METADATA)
            archive.writestr("rustleaks-1.2.3.dist-info/licenses/LICENSE", "MIT")
            archive.writestr("rustleaks-1.2.3.dist-info/licenses/third-party/index.json", "{}")

    def tearDown(self):
        self.directory.cleanup()

    def test_every_field_name_is_one_pypi_reads(self):
        names = {name for name, _ in upload.form_fields(self.wheel)}
        self.assertLessEqual(names, WAREHOUSE_FIELDS)
        self.assertEqual(
            names,
            WAREHOUSE_FIELDS - {"requires_dist"},
            "the wheel has no dependencies, so only requires_dist is absent",
        )

    def test_repeated_fields_carry_every_value(self):
        fields = upload.form_fields(self.wheel)
        values = lambda name: [value for field, value in fields if field == name]  # noqa: E731
        self.assertEqual(values("license_file"), ["LICENSE", "third-party/index.json"])
        self.assertEqual(values("classifiers"), ["Programming Language :: Python :: 3"])
        self.assertEqual(values("project_urls"), ["Homepage, https://example.com/"])
        self.assertEqual(values("license_expression"), ["MIT"])
        self.assertEqual(values("description"), ["# Readme\n"])


PYPROJECT = """[project]
name = "rustleaks"
version = "{version}"
description = "Scan bytes and text for secrets"
readme = "README.md"
requires-python = ">=3.12"
license = "MIT"
keywords = ["a", "b"]
classifiers = ["Programming Language :: Python :: 3"]

[project.urls]
Homepage = "https://example.com/"
"""


class CheckTest(unittest.TestCase):
    """`check` compares a pre-release wheel with pyproject.toml, which holds
    the PEP 440 version, such as 1.2.3a1 for the release 1.2.3-alpha.1."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.pyproject = os.path.join(self.directory.name, "pyproject.toml")
        with open(self.pyproject, "w", encoding="utf-8") as file:
            file.write(PYPROJECT.format(version="1.2.3a1"))
        with open(os.path.join(self.directory.name, "README.md"), "w", encoding="utf-8") as file:
            file.write("# Readme\n")

    def tearDown(self):
        self.directory.cleanup()

    def wheel(self, file_version, metadata_version):
        path = os.path.join(self.directory.name, f"rustleaks-{file_version}-py3-none-any.whl")
        metadata = METADATA.replace("Version: 1.2.3\n", f"Version: {metadata_version}\n")
        metadata = metadata.replace("License-File: LICENSE\n", "License-File: LICENSE\nLicense-File: NOTICE\n")
        dist_info = f"rustleaks-{file_version}.dist-info"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("rustleaks/__init__.py", "")
            archive.writestr(f"{dist_info}/METADATA", metadata)
            for name in ("LICENSE", "NOTICE", "third-party/index.json"):
                archive.writestr(f"{dist_info}/licenses/{name}", "text")
        return path

    def test_accepts_the_pep_440_version(self):
        upload.check(self.wheel("1.2.3a1", "1.2.3a1"), self.pyproject)

    def test_rejects_the_semantic_version(self):
        for file_version, metadata_version in [
            ("1.2.3_alpha.1", "1.2.3a1"),
            ("1.2.3a1", "1.2.3-alpha.1"),
            ("1.2.3", "1.2.3"),
        ]:
            with self.subTest(file_version=file_version, metadata_version=metadata_version):
                with self.assertRaises(SystemExit):
                    upload.check(self.wheel(file_version, metadata_version), self.pyproject)


if __name__ == "__main__":
    unittest.main()
