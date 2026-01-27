"""Structured error and warning types for constraint violations."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Severity(enum.Enum):
    """Constraint violation severity."""

    ERROR = "error"      # Stop pipeline
    WARNING = "warning"  # Continue + report


@dataclass(frozen=True)
class ConstraintViolation:
    """A single constraint violation with context.

    Attributes:
        severity: Whether this should stop the pipeline or just warn.
        code: Machine-readable violation code (e.g. 'missing_mac').
        message: Human-readable description of the violation.
        record_id: Identifier for the record that violated the constraint
            (e.g. 'Network:42' for sheet name + row number).
        field: Optional field name that caused the violation.
    """

    severity: Severity
    code: str
    message: str
    record_id: str = ""
    field: str = ""

    def __str__(self) -> str:
        prefix = self.severity.value.upper()
        loc = f" [{self.record_id}]" if self.record_id else ""
        return f"{prefix}{loc}: {self.message}"


@dataclass
class ValidationResult:
    """Aggregated result of running constraints.

    Collects all violations and provides summary methods.
    """

    violations: list[ConstraintViolation]

    def __init__(self) -> None:
        self.violations = []

    def add(self, violation: ConstraintViolation) -> None:
        self.violations.append(violation)

    @property
    def errors(self) -> list[ConstraintViolation]:
        return [v for v in self.violations if v.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[ConstraintViolation]:
        return [v for v in self.violations if v.severity == Severity.WARNING]

    @property
    def has_errors(self) -> bool:
        return any(v.severity == Severity.ERROR for v in self.violations)

    @property
    def is_valid(self) -> bool:
        return not self.has_errors

    def report(self) -> str:
        """Generate a human-readable report of all violations."""
        if not self.violations:
            return "No violations found."

        lines = []
        errors = self.errors
        warnings = self.warnings
        if errors:
            lines.append(f"{len(errors)} error(s):")
            for v in errors:
                lines.append(f"  {v}")
        if warnings:
            lines.append(f"{len(warnings)} warning(s):")
            for v in warnings:
                lines.append(f"  {v}")
        return "\n".join(lines)
