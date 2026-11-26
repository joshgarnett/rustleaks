"""Scan bytes and text for secrets with the Rustleaks engine.

>>> import rustleaks
>>> config = '''
... [[rules]]
... id = "example-marker"
... regex = 'MARK-([A-Z]{4})'
... secretGroup = 1
... keywords = ["mark-"]
... '''
>>> with rustleaks.Engine(config=config) as engine:
...     findings = engine.scan(b"name = MARK-ABCD\\n", path="config/app.env")
>>> [(f.rule_id, f.secret, f.start_line, f.secret_range) for f in findings]
[('example-marker', b'ABCD', 1, range(12, 16))]

See https://github.com/joshgarnett/rustleaks/blob/main/docs/user/python.md
for the guide.
"""

from ._engine import CancelToken, Engine
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
from ._version import __version__

__all__ = [
    "UNLIMITED",
    "BudgetExceededError",
    "Budget",
    "CancelToken",
    "ClosedError",
    "ConfigError",
    "Engine",
    "Error",
    "Finding",
    "IncompleteScanError",
    "InputTooLargeError",
    "LibraryError",
    "Rule",
    "ScanCancelledError",
    "ScanTimeoutError",
    "TextEncodingError",
    "Usage",
    "__version__",
]
