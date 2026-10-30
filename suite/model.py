# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field

from scope import ContextFactory


@dataclass(frozen=True)
class Observation:
    """A case's errno, return code, message, and observed values."""

    errno: int | None = None
    returncode: int | None = None
    message: str = ""
    observed: tuple[str, ...] = ()


@dataclass
class CaseState:
    """Mutable state shared by one case's child-process phases."""

    resources: ExitStack
    observed: list[str] = field(default_factory=list)
    opened_file: int | None = None


CaseStep = Callable[[CaseState], None]
Trigger = Callable[[CaseState], Observation]
Check = Callable[[Observation], str | None]


@dataclass(frozen=True)
class Case:
    id: str
    trigger: Trigger | None = None
    collect: tuple[CaseStep, ...] = ()
    setup: tuple[CaseStep, ...] = ()
    checks: tuple[Check, ...] = ()
    extra_scopes: tuple[ContextFactory, ...] = ()


@dataclass(frozen=True)
class Batch:
    id: str
    cases: tuple[Case, ...]
    setup: tuple[Callable, ...] = ()
    extra_scopes: tuple[ContextFactory, ...] = ()
    # Run after ordinary cleanup without restoring common IPE state.
    terminal: bool = False
