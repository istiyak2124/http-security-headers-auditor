from headers_auditor.checks import check_x_content_type_options
from headers_auditor.models import Severity
from headers_auditor.checks import check_x_frame_options

from headers_auditor.checks import (
    check_x_content_type_options,
    check_x_frame_options,
    check_hsts,
)

from headers_auditor.checks import (
    check_x_content_type_options,
    check_x_frame_options,
    check_hsts,
    check_csp,
)

from headers_auditor.checks import (
    check_x_content_type_options,
    check_x_frame_options,
    check_hsts,
    check_csp,
    check_referrer_policy,
)

from headers_auditor.checks import (
    check_x_content_type_options,
    check_x_frame_options,
    check_hsts,
    check_csp,
    check_referrer_policy,
    check_permissions_policy,
)


def test_missing_x_content_type_options():
    findings = check_x_content_type_options({})

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].header == "X-Content-Type-Options"


def test_invalid_x_content_type_options():
    headers = {"X-Content-Type-Options": "wrong"}

    findings = check_x_content_type_options(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_valid_x_content_type_options():
    headers = {"X-Content-Type-Options": "nosniff"}

    findings = check_x_content_type_options(headers)

    assert findings == []


def test_missing_x_frame_options():
    findings = check_x_frame_options({})

    assert len(findings) == 1
    assert findings[0].header == "X-Frame-Options"
    assert findings[0].severity == Severity.MEDIUM


def test_valid_x_frame_options():
    findings = check_x_frame_options(
        {"X-Frame-Options": "DENY"}
    )

    assert findings == []


def test_invalid_x_frame_options():
    findings = check_x_frame_options(
        {"X-Frame-Options": "INVALID"}
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_missing_hsts():
    findings = check_hsts({})

    assert len(findings) == 1
    assert findings[0].header == "Strict-Transport-Security"
    assert findings[0].severity == Severity.HIGH


def test_valid_hsts():
    headers = {
        "Strict-Transport-Security": "max-age=31536000"
    }

    findings = check_hsts(headers)

    assert findings == []


def test_hsts_with_zero_max_age():
    headers = {
        "Strict-Transport-Security": "max-age=0"
    }

    findings = check_hsts(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_hsts_without_max_age():
    headers = {
        "Strict-Transport-Security": "includeSubDomains"
    }

    findings = check_hsts(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_missing_csp():
    findings = check_csp({})

    assert len(findings) == 1
    assert findings[0].header == "Content-Security-Policy"
    assert findings[0].severity == Severity.HIGH


def test_empty_csp():
    headers = {"Content-Security-Policy": "   "}

    findings = check_csp(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_valid_csp():
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'"
    }

    findings = check_csp(headers)

    assert findings == []


def test_csp_with_no_directives():
    headers = {"Content-Security-Policy": " ; ; "}

    findings = check_csp(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_missing_referrer_policy():
    findings = check_referrer_policy({})

    assert len(findings) == 1
    assert findings[0].header == "Referrer-Policy"
    assert findings[0].severity == Severity.MEDIUM


def test_valid_referrer_policy():
    headers = {
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }

    findings = check_referrer_policy(headers)

    assert findings == []


def test_invalid_referrer_policy():
    headers = {"Referrer-Policy": "invalid-policy"}

    findings = check_referrer_policy(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_referrer_policy_multiple_values():
    headers = {
        "Referrer-Policy": "invalid-policy, no-referrer"
    }

    findings = check_referrer_policy(headers)

    assert findings == []


def test_missing_permissions_policy():
    findings = check_permissions_policy({})

    assert len(findings) == 1
    assert findings[0].header == "Permissions-Policy"
    assert findings[0].severity == Severity.LOW


def test_empty_permissions_policy():
    headers = {"Permissions-Policy": "   "}

    findings = check_permissions_policy(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_present_permissions_policy():
    headers = {
        "Permissions-Policy": "camera=(), microphone=()"
    }

    findings = check_permissions_policy(headers)

    assert findings == []


def test_lowercase_x_content_type_options():
    headers = {
        "x-content-type-options": "nosniff"
    }

    findings = check_x_content_type_options(headers)

    assert findings == []


def test_lowercase_x_frame_options():
    headers = {"x-frame-options": "DENY"}

    findings = check_x_frame_options(headers)

    assert findings == []


def test_lowercase_hsts():
    headers = {
        "strict-transport-security": "max-age=31536000"
    }

    findings = check_hsts(headers)

    assert findings == []


def test_lowercase_csp():
    headers = {
        "content-security-policy": "default-src 'self'"
    }

    findings = check_csp(headers)

    assert findings == []


def test_lowercase_permissions_policy():
    headers = {
        "permissions-policy": "camera=(), microphone=()"
    }

    findings = check_permissions_policy(headers)

    assert findings == []



def test_lowercase_referrer_policy():
    headers = {
        "referrer-policy": "strict-origin-when-cross-origin"
    }

    findings = check_referrer_policy(headers)

    assert findings == []



def test_hsts_with_duplicate_max_age():
    headers = {
        "Strict-Transport-Security":
            "max-age=31536000; max-age=0"
    }

    findings = check_hsts(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_hsts_with_non_numeric_max_age():
    headers = {
        "Strict-Transport-Security": "max-age=abc"
    }

    findings = check_hsts(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_empty_hsts():
    headers = {"Strict-Transport-Security": ""}

    findings = check_hsts(headers)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_x_frame_options_missing_but_csp_frame_ancestors_present():
    headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"
    }

    findings = check_x_frame_options(headers)

    assert findings == []
