"""Values that the rustleaks package returns or takes: findings, rules,
budgets and usage."""

from __future__ import annotations

import dataclasses
from typing import NoReturn

__all__ = ["UNLIMITED", "Budget", "Finding", "Rule", "Usage"]

#: A budget or input limit with this value is off.
UNLIMITED: int = 2**64 - 1


@dataclasses.dataclass(frozen=True, slots=True)
class Rule:
    """A rule of an engine that can report findings."""

    id: str
    description: str
    tags: tuple[str, ...]
    keywords: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    """One finding.

    ``secret``, ``match`` and ``line`` are bytes of the input. ``repr`` and
    ``str`` leave them out. ``start_line``, ``end_line``, ``start_column``
    and ``end_column`` follow the rules of the ``rustleaks`` reports: lines
    count from 1, and columns count bytes from 1, plus 1 on every line after
    the first. A finding of a rule with only a path pattern has line and
    column 0. On every line after the first, ``line`` starts with the line
    break that ends the line before it. ``secret_range`` and
    ``match_range`` are byte offsets into the input, or ``None`` when no
    exact range exists, as for decoded text.
    ``path`` is the path given to the scan.

    Findings cannot be pickled, because they hold secrets.
    """

    rule_id: str
    description: str
    tags: tuple[str, ...]
    secret: bytes = dataclasses.field(repr=False)
    match: bytes = dataclasses.field(repr=False)
    line: bytes = dataclasses.field(repr=False)
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    secret_range: range | None
    match_range: range | None
    entropy: float
    path: str | None

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise TypeError("cannot pickle a rustleaks Finding, because it holds a secret")

    def __copy__(self) -> Finding:
        return self

    def __deepcopy__(self, memo: object) -> Finding:
        return self


def _check_limit(name: str, value: object) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int or None, not {type(value).__name__}")
    if not 0 <= value <= UNLIMITED:
        raise ValueError(f"{name} must be from 0 to rustleaks.UNLIMITED")


@dataclasses.dataclass(frozen=True, slots=True)
class Budget:
    """Limits for one scan.

    Each field is a number, ``UNLIMITED`` to turn that limit off, or
    ``None`` to keep the value that applies already: the engine's value for
    a scan, or the library default for an engine. The library default is
    100,000 finding records and no other limit. A scan that reaches a limit
    raises ``BudgetExceededError``.
    """

    decoded_bytes: int | None = None
    work_units: int | None = None
    finding_records: int | None = None
    finding_payload_bytes: int | None = None
    collected_spans: int | None = None
    normalization_bytes: int | None = None

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            _check_limit(f"Budget.{field.name}", getattr(self, field.name))


@dataclasses.dataclass(frozen=True, slots=True)
class Usage:
    """What a scan used, in the units of the matching ``Budget`` fields."""

    decoded_bytes: int = 0
    work_units: int = 0
    finding_records: int = 0
    finding_payload_bytes: int = 0
    collected_spans: int = 0
    normalization_bytes: int = 0
