"""Tests for constraint error types."""

from gdoc2netcfg.constraints.errors import (
    ConstraintViolation,
    Severity,
    ValidationResult,
)


class TestConstraintViolation:
    def test_str_with_record_id(self):
        v = ConstraintViolation(
            severity=Severity.ERROR,
            code="test",
            message="Something broke",
            record_id="Network:42",
        )
        assert str(v) == "ERROR [Network:42]: Something broke"

    def test_str_without_record_id(self):
        v = ConstraintViolation(
            severity=Severity.WARNING,
            code="test",
            message="Something odd",
        )
        assert str(v) == "WARNING: Something odd"


class TestValidationResult:
    def test_empty_is_valid(self):
        result = ValidationResult()
        assert result.is_valid
        assert not result.has_errors

    def test_warnings_dont_make_invalid(self):
        result = ValidationResult()
        result.add(ConstraintViolation(
            severity=Severity.WARNING, code="w", message="warn"
        ))
        assert result.is_valid
        assert len(result.warnings) == 1
        assert len(result.errors) == 0

    def test_errors_make_invalid(self):
        result = ValidationResult()
        result.add(ConstraintViolation(
            severity=Severity.ERROR, code="e", message="err"
        ))
        assert not result.is_valid
        assert result.has_errors

    def test_report_no_violations(self):
        result = ValidationResult()
        assert "No violations" in result.report()

    def test_report_with_violations(self):
        result = ValidationResult()
        result.add(ConstraintViolation(
            severity=Severity.ERROR, code="e", message="err"
        ))
        result.add(ConstraintViolation(
            severity=Severity.WARNING, code="w", message="warn"
        ))
        report = result.report()
        assert "1 error(s)" in report
        assert "1 warning(s)" in report
