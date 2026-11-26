"""Exceptions raised by the rustleaks package.

No exception holds scanned bytes, findings or the text given to
``scan_text``. A ``ConfigError`` message can quote configuration text.
"""

from __future__ import annotations

from typing import Literal

from ._types import Usage

__all__ = [
    "BudgetExceededError",
    "ClosedError",
    "ConfigError",
    "Error",
    "IncompleteScanError",
    "InputTooLargeError",
    "LibraryError",
    "ScanCancelledError",
    "ScanTimeoutError",
    "TextEncodingError",
]

Termination = Literal["cancelled", "timeout", "budget", "other"]
BudgetName = Literal[
    "decoded_bytes",
    "work_units",
    "finding_records",
    "finding_payload_bytes",
    "collected_spans",
    "normalization_bytes",
]


def _rebuild(cls: type[Error], message: str) -> Error:
    error = cls.__new__(cls)
    BaseException.__init__(error, message)
    return error


class Error(Exception):
    """The base class of every rustleaks error."""

    def __reduce__(self) -> tuple[object, ...]:
        # The subclasses take more arguments than the message, so rebuild
        # them from the message and their attributes.
        message = self.args[0] if self.args else ""
        return (_rebuild, (type(self), message), self.__dict__)


class LibraryError(Error):
    """The native library is missing, cannot load, or has another version."""


class ConfigError(Error):
    """The configuration or the rule selection is not valid.

    ``kind`` is ``"config"`` for a configuration that does not load and
    ``"rule_selection"`` for a rule ID that the configuration does not have.
    The message is the full message of the library and can quote
    configuration text.
    """

    kind: Literal["config", "rule_selection"]

    def __init__(self, message: str, kind: Literal["config", "rule_selection"]) -> None:
        super().__init__(message)
        self.kind = kind


class InputTooLargeError(Error):
    """The input is longer than the engine's input limit.

    ``size`` is the input length in bytes, or for ``scan_text`` the length
    that was known when the check failed. ``limit`` is the limit in bytes.
    """

    size: int
    limit: int

    def __init__(self, message: str, size: int, limit: int) -> None:
        super().__init__(message)
        self.size = size
        self.limit = limit


class ClosedError(Error):
    """The engine is closed, or was created before this process forked."""


class TextEncodingError(Error):
    """The text given to ``scan_text`` cannot be encoded as UTF-8.

    ``position`` is the index of the first character that cannot be encoded,
    such as a lone surrogate. The exception does not hold the text.
    """

    position: int

    def __init__(self, message: str, position: int) -> None:
        super().__init__(message)
        self.position = position


class IncompleteScanError(Error):
    """The scan stopped before it finished, so it has no full result.

    ``termination`` says why: ``"cancelled"``, ``"timeout"``, ``"budget"``,
    or ``"other"`` for a reason this version does not name. For a budget,
    ``budget`` names it and ``limit``, ``consumed`` and ``requested`` give
    the limit, the amount used and the amount asked for; otherwise they are
    ``None``. ``usage`` is what the scan used before it stopped.
    """

    termination: Termination
    budget: BudgetName | None
    limit: int | None
    consumed: int | None
    requested: int | None
    usage: Usage

    def __init__(
        self,
        message: str,
        *,
        termination: Termination,
        usage: Usage,
        budget: BudgetName | None = None,
        limit: int | None = None,
        consumed: int | None = None,
        requested: int | None = None,
    ) -> None:
        super().__init__(message)
        self.termination = termination
        self.usage = usage
        self.budget = budget
        self.limit = limit
        self.consumed = consumed
        self.requested = requested


class ScanCancelledError(IncompleteScanError):
    """The scan's ``CancelToken`` was cancelled."""


class ScanTimeoutError(IncompleteScanError):
    """The scan's timeout passed before a worker was free or the scan ended."""


class BudgetExceededError(IncompleteScanError):
    """A budget ran out. ``budget``, ``limit``, ``consumed`` and
    ``requested`` describe it."""
