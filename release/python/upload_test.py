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


if __name__ == "__main__":
    unittest.main()
